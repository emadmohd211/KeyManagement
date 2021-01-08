using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Diagnostics;
using System.Linq;
using System.ServiceProcess;
using System.Text;
using System.Threading.Tasks;
using DLPServer.Data.MySql;
using DLPServer.Data.MySql.Repositories;
using System.Data.Entity;
using DLPServer.Model;
using DLPServer.Domain.Contracts;
using DLPServer.Domain;
using DLPServer.Domain.Models;
using DLPServer.Data;
using System.Timers;
using DLPServer.KeyManagementConsole;
using System.Configuration;
using System.Security.Cryptography;
using System.IO;
using System.Runtime.InteropServices;
using System.Net;
using System.Net.Sockets;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Crypto.Parameters;

//using System.Security.Cryptography.RSACryptoServiceProvider;
//using Chilkat;






namespace DLPServer.KeyManagement
{
    public static class StringCipher
    {
        // This constant string is used as a "salt" value for the PasswordDeriveBytes function calls.
        // This size of the IV (in bytes) must = (keysize / 8).  Default keysize is 256, so the IV must be
        // 32 bytes long.  Using a 16 character string here gives us 32 bytes when converted to a byte array.
        private const string initVector = "keysafepassword2";

        // This constant is used to determine the keysize of the encryption algorithm.
        private const int keysize = 256;


        public static string Decrypt(string cipherText, string passPhrase)
        {
            byte[] initVectorBytes = Encoding.ASCII.GetBytes(initVector);
            byte[] cipherTextBytes = Convert.FromBase64String(cipherText);
            PasswordDeriveBytes password = new PasswordDeriveBytes(passPhrase, null);
            byte[] keyBytes = password.GetBytes(keysize / 8);
            RijndaelManaged symmetricKey = new RijndaelManaged();
            symmetricKey.Mode = CipherMode.CBC;
            ICryptoTransform decryptor = symmetricKey.CreateDecryptor(keyBytes, initVectorBytes);
            MemoryStream memoryStream = new MemoryStream(cipherTextBytes);
            CryptoStream cryptoStream = new CryptoStream(memoryStream, decryptor, CryptoStreamMode.Read);
            byte[] plainTextBytes = new byte[cipherTextBytes.Length];
            int decryptedByteCount = cryptoStream.Read(plainTextBytes, 0, plainTextBytes.Length);
            memoryStream.Close();
            cryptoStream.Close();
            return Encoding.UTF8.GetString(plainTextBytes, 0, decryptedByteCount);
        }
    }


    public partial class KeyGenerationService : ServiceBase
    {
        private readonly IKeyGenerator keyGenerator = new KeyGenerator();
        private static Timer timer1;
        private bool authorised = true;
        DateTime lastCheck;
        private string phpPath;
        private string ss3serverPath;
        private IKeyTableRepository keyTableRepository;
        DLPServer.Data.MySql.DLPServerDbContext iunitOfwork;
        byte[] decryptorKey;
        private bool canRunPhp = false;
        private string phpPathLast;
        private string ss3serverPathLast;
        public  byte[] encrypted = null;
        public  byte[] aes_key = null;
        public static IPAddress ipAddress = IPAddress.Parse("127.0.0.1");         // ipHostInfo.AddressList[0];
        public static IPEndPoint localEndPoint = new IPEndPoint(ipAddress, 8888);
        public static IPEndPoint nextEndPoint = new IPEndPoint(ipAddress, 90);
        public Socket listener, listener1;


        

        public KeyGenerationService()
        {
            InitializeComponent();
            // Init event log which can be seen in event viewer
            if (!System.Diagnostics.EventLog.SourceExists("Key Generation Service"))
            {
                System.Diagnostics.EventLog.CreateEventSource(
                    "Key Generation Service", "DLPService");
            }
            eventLog1.Source = "Key Generation Service";
            eventLog1.Log = "DLPService";

            this.ServiceName = "Key Generation Service";
            this.CanHandlePowerEvent = true;
            this.CanHandleSessionChangeEvent = true;
            this.CanPauseAndContinue = true;
            this.CanShutdown = true;
            this.CanStop = true;

            // This timer is created to check our database in a specified interval 
            lastCheck = new DateTime(2000, 1, 1);
            timer1 = new Timer();
            GC.KeepAlive(timer1);

            eventLog1.WriteEntry("Service Initilization done...");
        }
        /*     public void Start()
             {
                 OnStart(new string[0]);
             }*/
        public void onDebug()
        {
            OnStart(null);
        }


        protected override void OnStart(string[] args)
        {

            // Create a TCP/IP socket.
             listener = new Socket(AddressFamily.InterNetwork,
                SocketType.Stream, ProtocolType.Tcp);
             listener.Bind(localEndPoint);
             listener1 = new Socket(AddressFamily.InterNetwork,
                 SocketType.Stream, ProtocolType.Tcp);
             listener1.Bind(nextEndPoint);
     
     
            eventLog1.WriteEntry("Service Started", EventLogEntryType.Information);
            timer1.Elapsed += new ElapsedEventHandler(timer1_Elapsed);
            timer1.Enabled = true;
            //set the interval to trigger timer for every 10 seconds
            timer1.Interval = (1000 * 10);
            timer1.AutoReset = false;
            timer1.Start();

        }

        private void timer1_Elapsed(object sender, ElapsedEventArgs e)
        {
            //eventLog1.WriteEntry("Timer ticked", EventLogEntryType.Information);
            try
            {
                File.WriteAllText(@"c:\cryp\log4.txt", "b4 monitorDatabase");
              //  this.MonitorDatabaseBasic();  // Basic version - keys held exposed within database
               // if (!authorised) this.CheckAuthorisation(); // trusted version - keys held encrypted with keysafe / user keys 
                if (authorised) this.MonitorDatabase();
                File.WriteAllText(@"c:\cryp\aftermonitor.txt", "b4 monitorDatabase");
                this.Listen_socketGetPublicKeyToEncrypt(); // USES SOCKETS TO GET KEYID ,GENERATES PRIVATE KEY, ENCRYPTS AND SENDS BACK TO CLIENT.
                       
                int count = 0;
                if (count % 90 == 0)
                {
                    count = 0;
                    eventLog1.WriteEntry("Fifteenth minute call of ExecutePHP to refresh users / user groups", EventLogEntryType.Information);
                    if (canRunPhp) ExecutePHP(phpPathLast, ss3serverPathLast);
                    if (canRunPhp) ExecuteSettingsPHP(phpPathLast, ss3serverPathLast);
                }
                count++;
                timer1.Start();
            }
            catch (Exception ex)
            {
                eventLog1.WriteEntry("error in timer_elapsed Method --" + ex.Message, EventLogEntryType.Error);
            }
        }

        protected override void OnStop()
        {
        }



        private void MonitorDatabaseBasic()
        {
     //       File.WriteAllText(@"c:\cryp\ret\log5.txt", "MonitorDatabaseBasic - 1");
            bool foundNewUsers = false;
            bool foundNewUserGroups = false;
           
            try
            {
               

                ExeConfigurationFileMap configMap = new ExeConfigurationFileMap();
                string path = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);
                path = path + @"\Guardware\DLP\dbsettings.config";
                File.WriteAllText(@"c:\cryp\path5.txt", path);
                configMap.ExeConfigFilename = path;
                Configuration config = ConfigurationManager.OpenMappedExeConfiguration(configMap, ConfigurationUserLevel.None);
                
                var connectionStringSection = (ConnectionStringsSection)config.GetSection("connectionStrings");
                string connStr = connectionStringSection.ConnectionStrings["ss3_dbContext"].ConnectionString;

                File.WriteAllText(@"c:\cryp\connthus.txt", connStr);

                string phpPath = config.AppSettings.Settings["PHPpath"].Value + @"\php.exe";
                string ss3serverPath = config.AppSettings.Settings["wwwroot"].Value + @"\ss3\server";

             

                // check if phpPath and ss3serverPath ok
                if (!Directory.Exists(ss3serverPath))
                {
                    eventLog1.WriteEntry("e-safe compliance IIS server path not found", EventLogEntryType.Information);
                    //                    return;
                }


                if (!File.Exists(phpPath)) 
                {
                    eventLog1.WriteEntry("IIS PHP path not found", EventLogEntryType.Information);
                    //                    return;
                }


                DLPServer.Data.MySql.DLPServerDbContext iunitOfwork = new Data.MySql.DLPServerDbContext();
           
                iunitOfwork.Database.Connection.ConnectionString = connStr;
                IKeyTableRepository keyTableRepository = new KeyTableRepository(iunitOfwork);
                IKeyGenerator keyGenerator = new KeyGenerator();

                try
                {
                    // generate an everyoneKeyPair if doesn't exist [actually only need to do this the first time!!]
                    if (!GenerateEveryoneKeyPairBasic(iunitOfwork, keyTableRepository))
                    {
                        // no database connection most likely so get out of there
                        eventLog1.WriteEntry("Cannot connect to database", EventLogEntryType.Information);
                        return;
                    }
                    canRunPhp = true;
                    phpPathLast = phpPath;
                    ss3serverPathLast = ss3serverPath;
                    // Generate the SharePointKey if required 
                    GenerateSharePointKeyPairBasic(iunitOfwork, keyTableRepository);
                    //monitor users table for users without key and generate key for them
                    foundNewUsers = SyncUsersKeysBasic(iunitOfwork, keyTableRepository);
                    //monitor usergroups table for usergroups without key and generate key for them
                    foundNewUserGroups = SyncUserGroupsKeysBasic(iunitOfwork, keyTableRepository);
                }
                catch (Exception ex)
                {
                    eventLog1.WriteEntry(ex.Message, EventLogEntryType.Information);
                }

                if (foundNewUsers || foundNewUserGroups)
                {
                    eventLog1.WriteEntry("New user or user group calling ExecutePHP", EventLogEntryType.Information);
                    ExecutePHP(phpPath, ss3serverPath);
                }

            }
            catch (Exception ex)
            {
                eventLog1.WriteEntry("error in Monitor Database Method --" + ex.Message, EventLogEntryType.Error);
            }
        }



        private void CheckAuthorisation()
        {

            try
            {

                ExeConfigurationFileMap configMap = new ExeConfigurationFileMap();
                string path = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);
                path = path + @"\Guardware\DLP\dbsettings.config";
                DateTime lastModified = System.IO.File.GetLastWriteTime(path);

                if (lastModified <= lastCheck)
                {
                    eventLog1.WriteEntry("No change to the config settings file", EventLogEntryType.Information);
                    return;
                }

                configMap.ExeConfigFilename = path;
                Configuration config = ConfigurationManager.OpenMappedExeConfiguration(configMap, ConfigurationUserLevel.None);
                var connectionStringSection = (ConnectionStringsSection)config.GetSection("connectionStrings");
                string connStr = connectionStringSection.ConnectionStrings["ss3_dbContext"].ConnectionString;

                phpPath = config.AppSettings.Settings["PHPpath"].Value + @"\php.exe";
                ss3serverPath = config.AppSettings.Settings["wwwroot"].Value + @"\ss3\server";
                string myDateTime = config.AppSettings.Settings["datetime"].Value;
                string myHash1 = config.AppSettings.Settings["hash1"].Value;
                string myHash2 = config.AppSettings.Settings["hash2"].Value;
                File.WriteAllText(@"c:\cryp\myDateTime.txt", myDateTime);

                AppSettingsSection appSection = config.GetSection("appSettings") as AppSettingsSection;
               

                // reset the hash values and safe the config file
                config.AppSettings.Settings["hash1"].Value = "aaaaaaaaaaaaaaaaaaaaaaaa";
                config.AppSettings.Settings["hash2"].Value = "aaaaaaaaaaaaaaaaaaaaaaaa";
              

                if ((!(appSection.ElementInformation.IsLocked)) &&
                    (!(appSection.SectionInformation.IsLocked)))
                {
                    if (!appSection.SectionInformation.IsProtected)
                    {
                        //this line will encrypt the file
                        appSection.SectionInformation.ProtectSection("DataProtectionConfigurationProvider");
                    }
                } 

          
                // save the change and generate the last check time (10 miliseconds after now)
                config.Save(ConfigurationSaveMode.Modified, true);
                lastCheck = System.IO.File.GetLastWriteTime(path);
            


                // check if phpPath and ss3serverPath ok
                if (!Directory.Exists(ss3serverPath))
                {
                    eventLog1.WriteEntry("e-safe compliance IIS server path not found", EventLogEntryType.Information);
                    return;
                }


                if (!File.Exists(phpPath))
                {
                    eventLog1.WriteEntry("IIS PHP path not found", EventLogEntryType.Information);
                    return;
                }

                File.WriteAllText(@"c:\cryp\xx4.txt", path);

                // check date time is in last 20 seconds 
                string earlierTime = DateTime.Now.AddSeconds(-20).ToString("yyyyMMdd HHmmss");
                File.WriteAllText(@"c:\cryp\earlierTime.txt", earlierTime);

                string nowTime = DateTime.Now.ToString("yyyyMMdd HHmmss");

                File.WriteAllText(@"c:\cryp\nowTime.txt", nowTime);
                if (string.Compare(earlierTime, myDateTime) > 0 || string.Compare(nowTime, myDateTime) < 0)
                {
                    eventLog1.WriteEntry("Key Management Service is not authorized - 1", EventLogEntryType.Information);
                    return;
                }
                File.WriteAllText(@"c:\cryp\hashh2.txt", path);

                // decrypt the password and the keyType
                string myKeyType = StringCipher.Decrypt(myHash1, path);
                string myPassword = StringCipher.Decrypt(myHash2, path);
                File.WriteAllText(@"c:\cryp\mykeytype11txt", myKeyType);
                File.WriteAllText(@"c:\cryp\myPassword11.txt", myPassword);
         
                File.WriteAllText(@"c:\cryp\hashh3.txt", path);

                // Check to see password is valid for keyType
                eventLog1.WriteEntry("now contacting database", EventLogEntryType.Information);
                iunitOfwork = new Data.MySql.DLPServerDbContext();
                iunitOfwork.Database.Connection.ConnectionString = connStr;
                keyTableRepository = new KeyTableRepository(iunitOfwork);
                IKeyGenerator keyGenerator = new KeyGenerator();
                try
                {
                    KeyPair decryptor;
                    KeyTypes keytype = KeyTypes.Person1;
                    bool keyTypeFound = false;
                    if (string.Compare(KeyTypes.Person1.ToString(), myKeyType) == 0)
                    {
                        keytype = KeyTypes.Person1;
                        keyTypeFound = true;
                    }
                    if (string.Compare(KeyTypes.Person2.ToString(), myKeyType) == 0)
                    {
                        keytype = KeyTypes.Person2;
                        keyTypeFound = true;
                    }
                    if (string.Compare(KeyTypes.Distributor.ToString(), myKeyType) == 0)
                    {
                        keytype = KeyTypes.Distributor;
                        keyTypeFound = true;
                    }
                    if (!keyTypeFound)
                    {
                        eventLog1.WriteEntry("Key Management Service is not authorized - 2", EventLogEntryType.Information);
                        return;
                    }

                    decryptor = new KeyPair(keytype);
                    KeyTable keyTable = keyTableRepository.GetKeyTable(keytype);
                    KeyPair _keyPair = new KeyPair(keytype);
                    _keyPair.PrivateKeyByte = keyTable.PrivateKey;
                    _keyPair.PublickKeyByte = keyTable.PublicKey;
                    decryptor.PublickKeyByte = keyTable.PublicKey;
                    IKeySafe _keySafe = new DLPServer.Domain.KeySafe();
                    _keySafe.DecryptKeyWithPassword(_keyPair, System.Text.Encoding.UTF8.GetBytes(myPassword));
                    if (_keySafe.DecryptedKey == null)
                    {
                        eventLog1.WriteEntry("Key Management Service is not authorized - 3", EventLogEntryType.Information);
                        return;
                    }

                    KeyTable keySafeTable = keyTableRepository.GetKeyTable(KeyTypes.KeySafe);
                    KeyPair keySafePair = new KeyPair(KeyTypes.KeySafe);
                    keySafePair.PrivateKeyByte = keySafeTable.PrivateKey;
                    keySafePair.PublickKeyByte = keySafeTable.PublicKey;
                    KeyPair MajorKeyPair = new KeyPair(keytype);
                    MajorKeyPair.PrivateKeyByte = _keySafe.DecryptedKey;
                    _keySafe.DecryptKeySafe(keySafePair, MajorKeyPair);
                    decryptorKey = _keySafe.DecryptedKey;


                }
                catch (Exception ex)
                {
                    eventLog1.WriteEntry(ex.Message, EventLogEntryType.Information);
                }

                eventLog1.WriteEntry("process is now authorized", EventLogEntryType.Information);
                authorised = true;

            }
            catch (Exception ex)
            {
                eventLog1.WriteEntry("error in Monitor Database Method --" + ex.Message, EventLogEntryType.Error);
            }
        }



        private void MonitorDatabase()
        {
            bool foundNewUsers = false;
            bool foundNewUserGroups = false;
          
            try    //start
            {

                ExeConfigurationFileMap configMap = new ExeConfigurationFileMap();
                string path = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);
                path = path + @"\Guardware\DLP\dbsettings.config";
                configMap.ExeConfigFilename = path;
                Configuration config = ConfigurationManager.OpenMappedExeConfiguration(configMap, ConfigurationUserLevel.None);
                var connectionStringSection = (ConnectionStringsSection)config.GetSection("connectionStrings");

                  string connStr = connectionStringSection.ConnectionStrings["ss3_dbContext"].ConnectionString;

                string phpPath = config.AppSettings.Settings["PHPpath"].Value + @"\php.exe";
                string ss3serverPath = config.AppSettings.Settings["wwwroot"].Value + @"\ss3\server";

                // check if phpPath and ss3serverPath ok
                if (!Directory.Exists(ss3serverPath))
                {
                    eventLog1.WriteEntry("e-safe compliance IIS server path not found", EventLogEntryType.Information);
                    //                    return;
                }


                if (!File.Exists(phpPath))
                {
                    eventLog1.WriteEntry("IIS PHP path not found", EventLogEntryType.Information);
                    //                    return;
                }


                DLPServer.Data.MySql.DLPServerDbContext iunitOfwork = new Data.MySql.DLPServerDbContext();


                iunitOfwork.Database.Connection.ConnectionString = connStr;

           
                IKeyTableRepository keyTableRepository = new KeyTableRepository(iunitOfwork);

                IKeyGenerator keyGenerator = new KeyGenerator();   //

                try
                {
                    // generate an everyoneKeyPair if doesn't exist [actually only need to do this the first time!!]
                    if (!GenerateEveryoneKeyPair(iunitOfwork, keyTableRepository))
                    {
                        // no database connection most likely so get out of there
                        eventLog1.WriteEntry("Cannot connect to database", EventLogEntryType.Information);
                        return;
                    }
                    // Generate the SharePointKey if required 
                    GenerateSharePointKeyPair(iunitOfwork, keyTableRepository);

                    //monitor usergroups table for usergroups without key and generate key for them
                    foundNewUserGroups = SyncUserGroupsKeys(iunitOfwork, keyTableRepository);

                    // deal with the requests for the keys
                    HandleKeyRequests(iunitOfwork, keyTableRepository);
                   // DecryptPrivateKey(iunitOfwork, keyTableRepository);
                }
                catch (Exception ex)
                {
                    eventLog1.WriteEntry(ex.Message, EventLogEntryType.Information);
                    File.WriteAllText(@"c:\cryp\exception.txt", "here ");
                }

                if (foundNewUsers || foundNewUserGroups)
                {
                    ExecutePHP(phpPath, ss3serverPath);
                }
                //Monitor database for regeneration of public/private keys for all user groups
                try
                {
                    RegenerateGroupKeys(iunitOfwork, keyTableRepository);
                }
                catch (Exception ex)
                {
                    eventLog1.WriteEntry("error in RegenerateKeyPairs Method --" + ex.Message, EventLogEntryType.Error);
                }
            }
            catch (Exception ex)
            {
                eventLog1.WriteEntry("error in Monitor Database Method --" + ex.Message, EventLogEntryType.Error);
            }

        }


        private void ExecuteSettingsPHP(string phpPath, string ss3serverPath)
        {
            //           eventLog1.WriteEntry("KeyGen Service is calling the PHP script", EventLogEntryType.Information);
            //NOTE: change path according to your own PHP.exe file, if you have the proper environment variables setup, then you can just call PHP.exe directly without the path
            //           string call = @"""c:\inetpub\PHP\php.exe""";

            //To execute the PHP file.
            string param1 = @"-f";

            //the PHP wrapper class file location. NOTE: remember to enclose in " (quotes) if there is a space in the directory structure. 
            string param2 = @"""encrypt_service_manage_settings.php""";

            Process myProcess = new Process();

            // Start a new instance of this program but specify the 'spawned' version. using the PHP.exe file location as the first argument.
            //            ProcessStartInfo myProcessStartInfo = new ProcessStartInfo(call, "spawn");
            ProcessStartInfo myProcessStartInfo = new ProcessStartInfo(phpPath, "spawn");
            myProcessStartInfo.UseShellExecute = false;
            myProcessStartInfo.RedirectStandardOutput = true;
            //            myProcessStartInfo.WorkingDirectory = @"C:\inetpub\wwwroot\ss3\server";
            myProcessStartInfo.WorkingDirectory = ss3serverPath;

            //           eventLog1.WriteEntry("phpPath - " + phpPath, EventLogEntryType.Information);

            //           eventLog1.WriteEntry("WorkingDirectory - " + ss3serverPath, EventLogEntryType.Information);


            //Provide the other arguments.
            myProcessStartInfo.Arguments = string.Format("{0} {1}", param1, param2);

            //            eventLog1.WriteEntry("Arguments - " + myProcessStartInfo.Arguments, EventLogEntryType.Information);

            myProcess.StartInfo = myProcessStartInfo;

            //Execute the process
            myProcess.Start();

        }



        private void ExecutePHP(string phpPath, string ss3serverPath)
        {
            //           eventLog1.WriteEntry("KeyGen Service is calling the PHP script", EventLogEntryType.Information);
            //NOTE: change path according to your own PHP.exe file, if you have the proper environment variables setup, then you can just call PHP.exe directly without the path
            //           string call = @"""c:\inetpub\PHP\php.exe""";

            //To execute the PHP file.
            string param1 = @"-f";

            //the PHP wrapper class file location. NOTE: remember to enclose in " (quotes) if there is a space in the directory structure. 
            string param2 = @"""encrypt_service_generate_settings.php""";

            Process myProcess = new Process();

            // Start a new instance of this program but specify the 'spawned' version. using the PHP.exe file location as the first argument.
            //            ProcessStartInfo myProcessStartInfo = new ProcessStartInfo(call, "spawn");
            ProcessStartInfo myProcessStartInfo = new ProcessStartInfo(phpPath, "spawn");
            myProcessStartInfo.UseShellExecute = false;
            myProcessStartInfo.RedirectStandardOutput = true;
            //            myProcessStartInfo.WorkingDirectory = @"C:\inetpub\wwwroot\ss3\server";
            myProcessStartInfo.WorkingDirectory = ss3serverPath;

            //           eventLog1.WriteEntry("phpPath - " + phpPath, EventLogEntryType.Information);

            //           eventLog1.WriteEntry("WorkingDirectory - " + ss3serverPath, EventLogEntryType.Information);


            //Provide the other arguments.
            myProcessStartInfo.Arguments = string.Format("{0} {1}", param1, param2);

            //            eventLog1.WriteEntry("Arguments - " + myProcessStartInfo.Arguments, EventLogEntryType.Information);

            myProcess.StartInfo = myProcessStartInfo;

            //Execute the process
            myProcess.Start();

        }


        private bool GenerateEveryoneKeyPairBasic(DLPServer.Data.MySql.DLPServerDbContext iunitOfwork, IKeyTableRepository _keyTableRepository)
        {
            var indexes = iunitOfwork.Database.SqlQuery<int>("SELECT id FROM ss3_db.encrypt_keypair WHERE keyType = 6;");
            int count = 0;
            try
            {
                count = indexes.Count();
            }
            catch (Exception ex)
            {
                eventLog1.WriteEntry("an error in GenerateEveryoneKeyPair Method --" + ex.Message, EventLogEntryType.Error);
                return false;
            }
            if (count == 0)
            {
                eventLog1.WriteEntry("Generating 'everyone' keys now", EventLogEntryType.Information);

                IUserGroupRepository userGroupRepository = new UserGroupRepository(iunitOfwork);

                KeyPair userGroupKey = new KeyPair(KeyTypes.EveryoneKey);

                eventLog1.WriteEntry("before GeneratePublicPrivateKeyPair", EventLogEntryType.Information);

                userGroupKey = GeneratePublicPrivateKeyPair(userGroupKey, this.keyGenerator);

                eventLog1.WriteEntry("after GeneratePublicPrivateKeyPair", EventLogEntryType.Information);

                KeyTable newKey = new KeyTable();
                newKey.KeyType = KeyTypes.EveryoneKey;
                newKey.PrivateKey = userGroupKey.PrivateKeyByte;
                newKey.PublicKey = userGroupKey.PublickKeyByte;
                newKey.ReferenceId = 0;
                newKey.DateGenerated = DateTime.Today;
                newKey.Pending = true;
                newKey.Valid = true;
                newKey.GenerationHistoryID = 0;

                if (newKey.PublicKey == null) eventLog1.WriteEntry("public key is null", EventLogEntryType.Information);
                if (newKey.PrivateKey == null) eventLog1.WriteEntry("private key is null", EventLogEntryType.Information);
                eventLog1.WriteEntry("before  _keyTableRepository.Create", EventLogEntryType.Information);

                _keyTableRepository.Create(newKey);

                eventLog1.WriteEntry("Generating 'everyone' keys - finished", EventLogEntryType.Information);

            }
            return true;
        }

        private bool GenerateEveryoneKeyPair(DLPServer.Data.MySql.DLPServerDbContext iunitOfwork, IKeyTableRepository _keyTableRepository)
        {
            var indexes = iunitOfwork.Database.SqlQuery<int>("SELECT id FROM ss3_db.encrypt_keypair WHERE keyType = 6;");
            int count = 0;
            try
            {
                count = indexes.Count();
            }
            catch (Exception ex)
            {
                eventLog1.WriteEntry("an error in GenerateEveryoneKeyPair Method --" + ex.Message, EventLogEntryType.Error);
                return false;
            }
            if (count == 0)
            {
                eventLog1.WriteEntry("Generating 'everyone' keys", EventLogEntryType.Information);

                IUserGroupRepository userGroupRepository = new UserGroupRepository(iunitOfwork);

                KeyTable _keyTable = _keyTableRepository.GetKeyTable(KeyTypes.KeySafe);
                KeyPair keySafePair = new KeyPair(KeyTypes.KeySafe);  
                keySafePair.PublickKeyByte = _keyTable.PublicKey;
                KeySafe keySafe;
                KeyPair userGroupKey = new KeyPair(KeyTypes.EveryoneKey);
                userGroupKey = GeneratePublicPrivateKeyPair(userGroupKey, this.keyGenerator);
                keySafe = new KeySafe();
                keySafe.EncryptWithKeysafe(userGroupKey, keySafePair);
                KeyTable newKey = new KeyTable();
                newKey.KeyType = KeyTypes.EveryoneKey;
                newKey.PrivateKey = keySafe.EncryptedKey;
                newKey.PublicKey = userGroupKey.PublickKeyByte;
                newKey.ReferenceId = 0;
                newKey.DateGenerated = DateTime.Now;
                newKey.Pending = true;
                newKey.Valid = true;
                newKey.GenerationHistoryID = 0;
                //   _keyTableRepository.Create(newKey);

                if (newKey.PublicKey == null) eventLog1.WriteEntry("public key is null", EventLogEntryType.Information);
                if (newKey.PrivateKey == null) eventLog1.WriteEntry("private key is null", EventLogEntryType.Information);
                eventLog1.WriteEntry("before  _keyTableRepository.Create", EventLogEntryType.Information);

                _keyTableRepository.Create(newKey);

                eventLog1.WriteEntry("Generating 'everyone' keys - finished", EventLogEntryType.Information);

            }
            return true;
        }


        private bool GenerateSharePointKeyPairBasic(DLPServer.Data.MySql.DLPServerDbContext iunitOfwork, IKeyTableRepository _keyTableRepository)
        {
            var indexes = iunitOfwork.Database.SqlQuery<int>("SELECT id FROM ss3_db.encrypt_keypair WHERE keyType = 7;");
            var indexes2 = iunitOfwork.Database.SqlQuery<int>("SELECT 1 FROM ss3_db.encrypt_settings WHERE name = 'SHAREPOINT' and value = 'ON';");
            int count = 0;
            int count2 = 0;
            try
            {
                count = indexes.Count();
                count2 = indexes2.Count();
            }
            catch (Exception ex)
            {
                eventLog1.WriteEntry("an error in GenerateEveryoneKeyPair Method --" + ex.Message, EventLogEntryType.Error);
                return false;
            }
            if (count == 0 && count2 != 0)
            {
                eventLog1.WriteEntry("Generating 'SharePoint' keys now", EventLogEntryType.Information);

                IUserGroupRepository userGroupRepository = new UserGroupRepository(iunitOfwork);

                KeyPair userGroupKey = new KeyPair(KeyTypes.SharePointKey);

                eventLog1.WriteEntry("before GeneratePublicPrivateKeyPair", EventLogEntryType.Information);

                userGroupKey = GeneratePublicPrivateKeyPair(userGroupKey, this.keyGenerator);

                eventLog1.WriteEntry("after GeneratePublicPrivateKeyPair", EventLogEntryType.Information);

                KeyTable newKey = new KeyTable();
                newKey.KeyType = KeyTypes.SharePointKey;
                newKey.PrivateKey = userGroupKey.PrivateKeyByte;
                newKey.PublicKey = userGroupKey.PublickKeyByte;
                newKey.ReferenceId = 0;
                newKey.DateGenerated = DateTime.Today;
                newKey.Pending = true;
                newKey.Valid = true;
                newKey.GenerationHistoryID = 0;

                if (newKey.PublicKey == null) eventLog1.WriteEntry("public key is null", EventLogEntryType.Information);
                if (newKey.PrivateKey == null) eventLog1.WriteEntry("private key is null", EventLogEntryType.Information);
                eventLog1.WriteEntry("before  _keyTableRepository.Create", EventLogEntryType.Information);

                _keyTableRepository.Create(newKey);

                eventLog1.WriteEntry("Generating 'SharePoint' keys - finished", EventLogEntryType.Information);
                count = 1;

            }
            if (count == 1)
            {

                // get the sharepoint clients do not have the encryptedSPKey
                ISharePointRepository sharePointRepository = new SharePointRepository(iunitOfwork);
                List<SharePoint> clients = sharePointRepository.GetClientsWithoutKey();

                if (clients.Count > 0)
                {

                    // Get the sharepoint private key
                    eventLog1.WriteEntry("getting the sharepoint private key", EventLogEntryType.Information);

                    KeyTable _keyTable = _keyTableRepository.GetKeyTable(KeyTypes.SharePointKey);
                    KeyPair keySharePoint = new KeyPair(KeyTypes.SharePointKey);
                    keySharePoint.PrivateKeyByte = _keyTable.PrivateKey;

                    KeyTable _keyTable2 = _keyTableRepository.GetKeyTable(KeyTypes.EveryoneKey);
                    KeyPair keyEveryone = new KeyPair(KeyTypes.EveryoneKey);
                    keyEveryone.PrivateKeyByte = _keyTable2.PrivateKey;

                    eventLog1.WriteEntry("got the sharepoint private key", EventLogEntryType.Information);

                    foreach (SharePoint client in clients)
                    {

                        eventLog1.WriteEntry("client = " + client.ID.ToString(), EventLogEntryType.Information);

                        KeyPair clientKey = new KeyPair(KeyTypes.UserKey);
                        clientKey.PublickKeyByte = client.PublicKey;

                        eventLog1.WriteEntry("assign client key pair", EventLogEntryType.Information);

                        KeySafe keySafe;
                        keySafe = new KeySafe();

                        eventLog1.WriteEntry("assign key safe", EventLogEntryType.Information);

                        keySafe.EncryptWithKeysafe(keySharePoint, clientKey);

                        eventLog1.WriteEntry("key sharepoint encrypted ", EventLogEntryType.Information);

                        if (keySharePoint.PrivateKeyByte == null) eventLog1.WriteEntry("keySharePoint private key is null", EventLogEntryType.Information);
                        if (clientKey.PublickKeyByte == null) eventLog1.WriteEntry("client public key is null", EventLogEntryType.Information);
                        if (keySafe.EncryptedKey == null) eventLog1.WriteEntry("encrypted key is null", EventLogEntryType.Information);

                        KeySafe keySafe2;
                        keySafe2 = new KeySafe();

                        eventLog1.WriteEntry("assign key safe2", EventLogEntryType.Information);

                        keySafe2.EncryptWithKeysafe(keyEveryone, clientKey);

                        eventLog1.WriteEntry("key everyone encrypted ", EventLogEntryType.Information);

                        if (keyEveryone.PrivateKeyByte == null) eventLog1.WriteEntry("keySharePoint private key is null", EventLogEntryType.Information);
                        if (clientKey.PublickKeyByte == null) eventLog1.WriteEntry("client public key is null", EventLogEntryType.Information);
                        if (keySafe2.EncryptedKey == null) eventLog1.WriteEntry("encrypted key2 is null", EventLogEntryType.Information);

                        client.EncryptedSPKey = keySafe.EncryptedKey;
                        client.EncryptedAllKey = keySafe2.EncryptedKey;

                        sharePointRepository.Update(client);

                        eventLog1.WriteEntry("client updated ", EventLogEntryType.Information);

                    }
                }
            }

            return true;
        }


        private bool GenerateSharePointKeyPair(DLPServer.Data.MySql.DLPServerDbContext iunitOfwork, IKeyTableRepository _keyTableRepository)
        {
            var indexes = iunitOfwork.Database.SqlQuery<int>("SELECT id FROM ss3_db.encrypt_keypair WHERE keyType = 7;");
            var indexes2 = iunitOfwork.Database.SqlQuery<int>("SELECT 1 FROM ss3_db.encrypt_settings WHERE name = 'SHAREPOINT' and value = 'ON';");
            int count = 0;
            int count2 = 0;
            try
            {
                count = indexes.Count();
                count2 = indexes2.Count();
            }
            catch (Exception ex)
            {
                eventLog1.WriteEntry("an error in GenerateEveryoneKeyPair Method --" + ex.Message, EventLogEntryType.Error);
                return false;
            }
            if (count == 0 && count2 != 0)
            {
                eventLog1.WriteEntry("Generating 'SharePoint' keys now", EventLogEntryType.Information);

                IUserGroupRepository userGroupRepository = new UserGroupRepository(iunitOfwork);


                KeyTable _keyTable = _keyTableRepository.GetKeyTable(KeyTypes.KeySafe);
                KeyPair keySafePair = new KeyPair(KeyTypes.KeySafe);
                keySafePair.PublickKeyByte = _keyTable.PublicKey;
                KeySafe keySafe;
                KeyPair userGroupKey = new KeyPair(KeyTypes.SharePointKey);
                userGroupKey = GeneratePublicPrivateKeyPair(userGroupKey, this.keyGenerator);
                keySafe = new KeySafe();
                keySafe.EncryptWithKeysafe(userGroupKey, keySafePair);
                KeyTable newKey = new KeyTable();
                newKey.KeyType = KeyTypes.SharePointKey;
                newKey.PrivateKey = keySafe.EncryptedKey;
                newKey.PublicKey = userGroupKey.PublickKeyByte;
                newKey.ReferenceId = 0;
                newKey.DateGenerated = DateTime.Now;
                newKey.Pending = true;
                newKey.Valid = true;
                newKey.GenerationHistoryID = 0;
                _keyTableRepository.Create(newKey);

                eventLog1.WriteEntry("Generating 'SharePoint' keys - finished", EventLogEntryType.Information);
                count = 1;

            }
            if (count == 1)
            {

                // get the sharepoint clients do not have the encryptedSPKey
                ISharePointRepository sharePointRepository = new SharePointRepository(iunitOfwork);
                List<SharePoint> clients = sharePointRepository.GetClientsWithoutKey();

                if (clients.Count > 0)
                {

                    // Get the sharepoint private key
                    eventLog1.WriteEntry("getting the sharepoint private key", EventLogEntryType.Information);

                    KeyTable _keyTable = _keyTableRepository.GetKeyTable(KeyTypes.SharePointKey);
                    KeyPair keySharePoint = new KeyPair(KeyTypes.SharePointKey);
                    keySharePoint.PrivateKeyByte = _keyTable.PrivateKey;

                    KeyTable _keyTable2 = _keyTableRepository.GetKeyTable(KeyTypes.EveryoneKey);
                    KeyPair keyEveryone = new KeyPair(KeyTypes.EveryoneKey);
                    keyEveryone.PrivateKeyByte = _keyTable2.PrivateKey;

                    eventLog1.WriteEntry("got the sharepoint private key", EventLogEntryType.Information);

                    foreach (SharePoint client in clients)
                    {

                        eventLog1.WriteEntry("client = " + client.ID.ToString(), EventLogEntryType.Information);

                        KeyPair clientKey = new KeyPair(KeyTypes.UserKey);
                        clientKey.PublickKeyByte = client.PublicKey;

                        eventLog1.WriteEntry("assign client key pair", EventLogEntryType.Information);

                        KeySafe keySafe;
                        keySafe = new KeySafe();

                        eventLog1.WriteEntry("assign key safe", EventLogEntryType.Information);

                        keySafe.EncryptWithKeysafe(keySharePoint, clientKey);

                        eventLog1.WriteEntry("key sharepoint encrypted ", EventLogEntryType.Information);

                        if (keySharePoint.PrivateKeyByte == null) eventLog1.WriteEntry("keySharePoint private key is null", EventLogEntryType.Information);
                        if (clientKey.PublickKeyByte == null) eventLog1.WriteEntry("client public key is null", EventLogEntryType.Information);
                        if (keySafe.EncryptedKey == null) eventLog1.WriteEntry("encrypted key is null", EventLogEntryType.Information);

                        KeySafe keySafe2;
                        keySafe2 = new KeySafe();

                        eventLog1.WriteEntry("assign key safe2", EventLogEntryType.Information);

                        keySafe2.EncryptWithKeysafe(keyEveryone, clientKey);

                        eventLog1.WriteEntry("key everyone encrypted ", EventLogEntryType.Information);

                        if (keyEveryone.PrivateKeyByte == null) eventLog1.WriteEntry("keySharePoint private key is null", EventLogEntryType.Information);
                        if (clientKey.PublickKeyByte == null) eventLog1.WriteEntry("client public key is null", EventLogEntryType.Information);
                        if (keySafe2.EncryptedKey == null) eventLog1.WriteEntry("encrypted key2 is null", EventLogEntryType.Information);

                        client.EncryptedSPKey = keySafe.EncryptedKey;
                        client.EncryptedAllKey = keySafe2.EncryptedKey;

                        sharePointRepository.Update(client);

                        eventLog1.WriteEntry("client updated ", EventLogEntryType.Information);

                    }
                }
            }

            return true;
        }




        private bool RegenerateEveryoneKeyPair(DLPServer.Data.MySql.DLPServerDbContext iunitOfwork, IKeyTableRepository _keyTableRepository)
        {
            eventLog1.WriteEntry("Generating 'everyone' keys", EventLogEntryType.Information);

            IUserGroupRepository userGroupRepository = new UserGroupRepository(iunitOfwork);

            KeyTable _keyTable = _keyTableRepository.GetKeyTable(KeyTypes.KeySafe);
            KeyPair keySafePair = new KeyPair(KeyTypes.KeySafe);
            keySafePair.PublickKeyByte = _keyTable.PublicKey;
            KeySafe keySafe;
            KeyPair userGroupKey = new KeyPair(KeyTypes.EveryoneKey);
            userGroupKey = GeneratePublicPrivateKeyPair(userGroupKey, this.keyGenerator);
            keySafe = new KeySafe();
            keySafe.EncryptWithKeysafe(userGroupKey, keySafePair);
            KeyTable newKey = new KeyTable();
            newKey.KeyType = KeyTypes.EveryoneKey;
            newKey.PrivateKey = keySafe.EncryptedKey;
            newKey.PublicKey = userGroupKey.PublickKeyByte;
            newKey.ReferenceId = 0;
            newKey.DateGenerated = DateTime.Now;
            newKey.Pending = true;
            newKey.Valid = true;
            newKey.GenerationHistoryID = 0;
            _keyTableRepository.Create(newKey);
            return true;
        }

        private void RegenerateGroupKeys(DLPServer.Data.MySql.DLPServerDbContext iunitOfwork, IKeyTableRepository _keyTableRepository)
        {
            ISettingsRepository settingsRepository = new SettingsRepository(iunitOfwork);
            settings settingStart = settingsRepository.GetSetting("KEY_REGEN_START_DATE");
            settings settingLast = settingsRepository.GetSetting("KEY_REGEN_LAST_DATE");
            if (settingStart != null)
            {
                // if start date is less last date then do nothing
                if (settingLast != null)
                {
                    if (settingLast.value.CompareTo(settingStart.value) > 0) return;
                }
                // if now is less that start date, do nothing
                string nowTime = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss");
                if (nowTime.CompareTo(settingStart.value) < 0) return;

                // as gone pass start date and not posted a last revocation date do revocation work
                // delete contents of encrypt_usergroupkey
                IUserGroupRepository usergroupRepository = new UserGroupRepository(iunitOfwork);
                usergroupRepository.DeleteAllEntries();

                // create a new key pair for all users
                RegenerateEveryoneKeyPair(iunitOfwork, _keyTableRepository);

                // set the last date
                settings newLastDate = new settings();
                newLastDate.name = "KEY_REGEN_LAST_DATE";
                newLastDate.value = nowTime;
                settingsRepository.UpdateSetting(newLastDate);

            }
        }


        private bool SyncUserGroupsKeysBasic(DLPServer.Data.MySql.DLPServerDbContext iunitOfwork, IKeyTableRepository _keyTableRepository)
        {
            bool foundNewUserGroups = false;
            try
            {
                IUserGroupRepository userGroupRepository = new UserGroupRepository(iunitOfwork);
                List<ss3_usergroup> userGroups = userGroupRepository.GetUserGroupsWithoutKey();
                if (userGroups.Count > 0)
                {
                    foundNewUserGroups = true;
                    foreach (ss3_usergroup _userGroup in userGroups)
                    {
                        usergroup tempEncryptionUsergroup = new usergroup();
                        KeyPair userGroupKey = new KeyPair(KeyTypes.UserGroupKey);
                        userGroupKey = GeneratePublicPrivateKeyPair(userGroupKey, this.keyGenerator);
                        KeyTable newKey = new KeyTable();
                        newKey.KeyType = userGroupKey.KeyType;
                        newKey.PrivateKey = userGroupKey.PrivateKeyByte;
                        newKey.PublicKey = userGroupKey.PublickKeyByte;
                        newKey.ReferenceId = _userGroup.id;
                        newKey.DateGenerated = DateTime.Today;
                        newKey.Pending = false;
                        newKey.Valid = true;

                        tempEncryptionUsergroup.groupid = _userGroup.id;
                        tempEncryptionUsergroup.keyID = _keyTableRepository.Create(newKey);
                        userGroupRepository.Create(tempEncryptionUsergroup);
                        eventLog1.WriteEntry("keys were generated for usergroup id:" + _userGroup.id.ToString(), EventLogEntryType.Information);
                    }
                }
            }
            catch (Exception ex)
            {
                eventLog1.WriteEntry("an error in SyncUsersKeys Method --" + ex.Message, EventLogEntryType.Error);
            }

            return foundNewUserGroups;
        }



        private bool SyncUserGroupsKeys(DLPServer.Data.MySql.DLPServerDbContext iunitOfwork, IKeyTableRepository _keyTableRepository)
        {
            bool foundNewUserGroups = false;
            try
            {
                IUserGroupRepository userGroupRepository = new UserGroupRepository(iunitOfwork);
                KeyTable _keyTable = _keyTableRepository.GetKeyTable(KeyTypes.KeySafe);
                KeyPair keySafePair = new KeyPair(KeyTypes.KeySafe);
                keySafePair.PublickKeyByte = _keyTable.PublicKey;
                List<ss3_usergroup> userGroups = userGroupRepository.GetUserGroupsWithoutKey();
                if (userGroups.Count > 0)
                {
                    foundNewUserGroups = true;
                    KeySafe keySafe;
                    foreach (ss3_usergroup _userGroup in userGroups)
                    {
                        usergroup tempEncryptionUsergroup = new usergroup();
                        KeyPair userGroupKey = new KeyPair(KeyTypes.UserGroupKey);
                        userGroupKey = GeneratePublicPrivateKeyPair(userGroupKey, this.keyGenerator);
                        keySafe = new KeySafe();
                        keySafe.EncryptWithKeysafe(userGroupKey, keySafePair);
                        KeyTable newKey = new KeyTable();
                        newKey.KeyType = userGroupKey.KeyType;
                        newKey.PrivateKey = keySafe.EncryptedKey;
                        newKey.PublicKey = userGroupKey.PublickKeyByte;
                        newKey.ReferenceId = _userGroup.id;
                        newKey.DateGenerated = DateTime.Now;
                        newKey.Pending = false;
                        newKey.Valid = true;

                        tempEncryptionUsergroup.groupid = _userGroup.id;
                        tempEncryptionUsergroup.keyID = _keyTableRepository.Create(newKey);
                        userGroupRepository.Create(tempEncryptionUsergroup);
                        eventLog1.WriteEntry("keys were generated for usergroup id:" + _userGroup.id.ToString(), EventLogEntryType.Information);
                    }
                }
            }
            catch (Exception ex)
            {
                eventLog1.WriteEntry("an error in SyncUsersKeys Method --" + ex.Message, EventLogEntryType.Error);
            }

            return foundNewUserGroups;
        }




        private bool SyncUsersKeysBasic(DLPServerDbContext iunitOfwork, IKeyTableRepository _keyTableRepository)
        {
            bool foundNewUsers = false;
            try
            {
                IUserRepository userRepository = new UserRepository(iunitOfwork);
                IUserKeyRepository userKeyRepository = new UserKeyRepository(iunitOfwork);
                //get the list of users who need keys
                List<user> users = userRepository.GetUsersWithoutKey();
                if (users.Count > 0)
                {
                    foundNewUsers = true;
                    foreach (user _user in users)
                    {
                        eventLog1.WriteEntry("Generating keys for user:" + _user.id.ToString(), EventLogEntryType.Information);

                        KeyPair userKey = new KeyPair(KeyTypes.UserKey);
                        userKey = GeneratePublicPrivateKeyPair(userKey, this.keyGenerator);
                        KeyTable newKey = new KeyTable();
                        newKey.KeyType = userKey.KeyType;
                        newKey.PrivateKey = userKey.PrivateKeyByte;
                        newKey.PublicKey = userKey.PublickKeyByte;
                        newKey.ReferenceId = _user.id;
                        newKey.DateGenerated = DateTime.Today;
                        newKey.Pending = false;
                        newKey.Valid = true;

                        userkey newUserKey = new userkey();
                        newUserKey.userid = _user.id;
                        newUserKey.keyID = _keyTableRepository.Create(newKey);
                        newUserKey.isMobileUser = false;
                        userKeyRepository.Create(newUserKey);

                    }
                }
            }
            catch (Exception ex)
            {
                eventLog1.WriteEntry("an error in SyncUsersKeys Method --" + ex.Message, EventLogEntryType.Error);
            }

            return foundNewUsers;
        }


        private bool SyncUsersKeys(DLPServerDbContext iunitOfwork, IKeyTableRepository _keyTableRepository)
        {
            bool foundNewUsers = false;
            try
            {
                IUserRepository userRepository = new UserRepository(iunitOfwork);
                IUserKeyRepository userKeyRepository = new UserKeyRepository(iunitOfwork);
                //Get KeySafe for encrypting the user private key
                KeyTable _keyTable = _keyTableRepository.GetKeyTable(KeyTypes.KeySafe);
                KeyPair KeySafePair = new KeyPair(KeyTypes.KeySafe);
                KeySafePair.PublickKeyByte = _keyTable.PublicKey;
                //get the list of users who need keys
                List<user> users = userRepository.GetUsersWithoutKey();
                if (users.Count > 0)
                {
                    foundNewUsers = true;
                    KeySafe keySafe;
                    foreach (user _user in users)
                    {
                        eventLog1.WriteEntry("Generating keys for user:" + _user.id.ToString(), EventLogEntryType.Information);

                        KeyPair userKey = new KeyPair(KeyTypes.UserKey);
                        userKey = GeneratePublicPrivateKeyPair(userKey, this.keyGenerator);
                        keySafe = new KeySafe();
                        keySafe.EncryptWithKeysafe(userKey, KeySafePair);
                        KeyTable newKey = new KeyTable();
                        newKey.KeyType = userKey.KeyType;
                        newKey.KeySafeEncryptedFile = keySafe.EncryptedKey;
                        newKey.PrivateKey = userKey.PrivateKeyByte;
                        newKey.PublicKey = userKey.PublickKeyByte;
                        newKey.ReferenceId = _user.id;
                        newKey.DateGenerated = DateTime.Today;
                        newKey.Pending = false;
                        newKey.Valid = true;


                        userkey newUserKey = new userkey();
                        newUserKey.userid = _user.id;
                        newUserKey.keyID = _keyTableRepository.Create(newKey);
                        newUserKey.isMobileUser = false;
                        userKeyRepository.Create(newUserKey);

                    }
                }
            }
            catch (Exception ex)
            {
                eventLog1.WriteEntry("an error in SyncUsersKeys Method --" + ex.Message, EventLogEntryType.Error);
            }

            return foundNewUsers;
        }


        private void HandleKeyRequests(DLPServerDbContext iunitOfwork, IKeyTableRepository _keyTableRepository)
        {
            IUserKeyRepository userKeyRepository = new UserKeyRepository(iunitOfwork);
            IUserEncodeGroupNeedRepository userencodegroupneedRepository = new UserEncodeGroupNeedRepository(iunitOfwork);
            IUserEncodeGroupKeysRepository userencodegroupkeysRepository = new UserEncodeGroupKeysRepository(iunitOfwork);
            IKeyTableRepository keyTableRepository = new KeyTableRepository(iunitOfwork);


            // get list of user /  groups keys that need to be encoded
            List<userencodegroupneed> needed = userencodegroupneedRepository.GetEncodeNeed();


            if (needed.Count > 0)
            {

                foreach (userencodegroupneed _need in needed)
                {
                    // get the user public key for the _need.userId 
                    userkey userKey = userKeyRepository.GetUserKey(_need.userId);
                    KeyTable keyTableUser = keyTableRepository.GetKeyTable(userKey.keyID);

                    // get the group keysafe encrypted private key for the _need.keyId
                    KeyTable keyTableGroup = keyTableRepository.GetKeyTable(_need.keyId);


                   // File.WriteAllText(@"c:\cryp\ret\\komp.txt", _need.keyId.ToString() + ":::::" + keyTableGroup.PrivateKey + "::" + decryptorKey);

                    // decrypt the group keysafe encrypted private key
                    KeySafe keySafe = new KeySafe();
                    keySafe.DecryptWithPrivate(keyTableGroup.PrivateKey, decryptorKey);

                    // encrypt the decrypted group private key using the user public key.
                    keySafe.EncryptWithPublic(keySafe.DecryptedKey, keyTableUser.PublicKey);

                    // save to the userencodegroupkeys
                    userencodegroupkeys _newEncodeKey = new userencodegroupkeys();
                    _newEncodeKey.userId = _need.userId;
                    _newEncodeKey.keyId = _need.keyId;
                    _newEncodeKey.key = keySafe.EncryptedKey;
                    userencodegroupkeysRepository.Create(_newEncodeKey);

                    // delete the needed item
                    userencodegroupneedRepository.DeleteEncodeNeed(_need);
                }
            }
        }



        public KeyPair GeneratePublicPrivateKeyPair(KeyPair keyPair, IKeyGenerator keyGenerator)
        {
            try
            {
                eventLog1.WriteEntry("before keyGenerator.GeneratePublicPrivateKeyPair", EventLogEntryType.Information);
                keyGenerator.GeneratePublicPrivateKeyPair();
                eventLog1.WriteEntry("after keyGenerator.GeneratePublicPrivateKeyPair", EventLogEntryType.Information);
                keyPair.PrivateKey = keyGenerator.PrivateKey;
                keyPair.PublicKey = keyGenerator.PublicKey;
                keyPair.PrivateKeyByte = keyGenerator.PrivateKeyByte;
                keyPair.PublickKeyByte = keyGenerator.PublicKeyByte;
                return keyPair;
            }
            catch (InvalidOperationException ex)
            {
                throw new BusinessServicesException("", ex); 
            }

        }

        // decrypts the user asked key..................
        public byte[] DecryptPrivateKey(string _key)
        {
            byte[] bytes = new Byte[1024];
       
            byte[] result = null;
            //bool a = true;
            ExeConfigurationFileMap configMap = new ExeConfigurationFileMap();
            string path = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);
            File.WriteAllText(@"c:\cryp\path.txt", path);

            path = path + @"\Guardware\DLP\dbsettings.config";
           configMap.ExeConfigFilename = path;

            Configuration config = ConfigurationManager.OpenMappedExeConfiguration(configMap, ConfigurationUserLevel.None);
            var connectionStringSection = (ConnectionStringsSection)config.GetSection("connectionStrings");
            string connStr = null;
            connStr = connectionStringSection.ConnectionStrings["ss3_dbContext"].ConnectionString;

            File.WriteAllText(@"c:\cryp\connStr.txt", connStr);

            string myHash1 = config.AppSettings.Settings["hash1"].Value;
            string myHash2 = config.AppSettings.Settings["hash2"].Value;

            File.WriteAllText(@"c:\cryp\bind2.txt", "entered-join");
             // decrypt the password and the keyType
            string myKeyType =  StringCipher.Decrypt(myHash1, path);
            string myPassword = StringCipher.Decrypt(myHash2, path);
            File.WriteAllText(@"c:\cryp\mykeytype.txt", myKeyType);
            File.WriteAllText(@"c:\cryp\myPassword.txt", myPassword);
         
          
            DLPServer.Data.MySql.DLPServerDbContext iunitOfwork = new Data.MySql.DLPServerDbContext();
           
            iunitOfwork.Database.Connection.ConnectionString = connStr;
           

            IKeyTableRepository keyTableRepository = new KeyTableRepository(iunitOfwork);

                // Check to see password is valid for keyType
                eventLog1.WriteEntry("now contacting database", EventLogEntryType.Information);
 
                    KeyTypes keytype = KeyTypes.Person1;
                    bool keyTypeFound = false;
                    if (string.Compare(KeyTypes.Person1.ToString(), myKeyType) == 0)
                    {
                        keytype = KeyTypes.Person1;
                        keyTypeFound = true;
                    }
                    if (string.Compare(KeyTypes.Person2.ToString(), myKeyType) == 0)
                    {
                        keytype = KeyTypes.Person2;
                        keyTypeFound = true;
                    }
                    if (string.Compare(KeyTypes.Distributor.ToString(), myKeyType) == 0)
                    {
                        keytype = KeyTypes.Distributor;
                        keyTypeFound = true;
                    }
                    if (!keyTypeFound)
                    {
                        eventLog1.WriteEntry("Key Management Service is not authorized - 2", EventLogEntryType.Information);
                       
                    }

          
            try
            {
                    Key_safe ks = new Key_safe();
                    byte[] cipherText = new Byte[1024];
                    KeyTable keyTableUser = keyTableRepository.GetKeyTable(Int32.Parse(_key));
              //      File.WriteAllText(@"c:\cryp\maincheck.txt", _key);

                    //     Nullable<long> thisTypes =  keyTableGroup.ReferenceId;
                    KeyPair keyUserPair = new KeyPair(keyTableUser.KeyType);
                    keyUserPair.PrivateKeyByte = keyTableUser.PrivateKey;
                    keyUserPair.PublickKeyByte = keyTableUser.PublicKey;



                    KeyTable keySafeTable = keyTableRepository.GetKeyTable(KeyTypes.KeySafe);
                    KeyPair keySafePair = new KeyPair(KeyTypes.KeySafe);
                    keySafePair.PrivateKeyByte = keySafeTable.PrivateKey;
                    keySafePair.PublickKeyByte = keySafeTable.PublicKey;
                    int id = keySafeTable.ID;


                    KeyTable keyTableCEO = keyTableRepository.GetKeyTable(keytype);
                    //     Nullable<long> thisTypes =  keyTableGroup.ReferenceId;
                    KeyPair keyCeoPair = new KeyPair(keyTableCEO.KeyType);
                   // File.WriteAllText(@"c:\cryp\type.txt",keyTableCEO.KeyType.ToString());

                    keyCeoPair.PrivateKeyByte = keyTableCEO.PrivateKey;
                    keyCeoPair.PublickKeyByte = keyTableCEO.PublicKey;

                    //--------------- decrypt ceo key with password   -------------------------------------------------------
                    byte[] dp = ks.DecryptKeyWithPassword(keyCeoPair, System.Text.Encoding.UTF8.GetBytes(myPassword));
                    
                    KeyPair MajorKeyPair = new KeyPair(keyTableCEO.KeyType);
                    MajorKeyPair.PrivateKeyByte = dp;
                   
                     //--------------    ---------------------------------------------------------
                    byte[] dd = ks.DecryptKeySafe(keySafePair, MajorKeyPair);
                   

                    result = ks.DecryptWithPrivate(keyUserPair.PrivateKeyByte, dd);
                   File.WriteAllText(@"c:\cryp\resultSize.txt", (result.Length).ToString());

                  //  Listen_socketGetPublicKeyToEncrypt(result);


            }
            catch (Exception e)
            {
                Console.WriteLine(e.ToString());
            }
            return result;

        }
        // Implements sockets..................
        public void Listen_socketGetPublicKeyToEncrypt()
        {
            File.WriteAllText(@"c:\cryp\one.txt","entered");

            // Data buffer for incoming data.
            try {
                Socket handler = null, handler2 = null;
                // this encrypts the private key by AES....
                byte[] aes_encrypted = join_conn(listener, handler, null, 1);

                File.WriteAllText(@"c:\cryp\btwnjoin.txt", "entered");
                // this encrypts AES KEY with RSA............
                byte[] encryptd_key = join_conn(listener1, handler2,aes_key, 2);
           //     File.WriteAllText(@"c:\cryp\btwnjoin.txt", "entered");

            }
            catch (SocketException ex)
            {
                eventLog1.WriteEntry("error in socket Method --" + ex.Message, EventLogEntryType.Error);
            }

        }
        // connects to the sockets to receive and send the data..............
        public byte[] join_conn(Socket listener, Socket handler, byte[] _key,int _conn)
        {
            byte[] result = null;
            string _data;
            try
            {
                listener.Listen(10);

                bool a = true;
                // Start listening for connections.
                while (a)
                {
                   // File.WriteAllText(@"c:\cryp\while.txt", "entered-join");

                    Console.WriteLine("Waiting for a connection...");
                    // Program is suspended while waiting for an incoming connection.
                    handler = listener.Accept();
                  //  System.Threading.Thread.Sleep(100);
                    Console.WriteLine(handler);
                    _data = null;
                    _data = Receive_data(handler);
                    File.WriteAllText(@"c:\cryp\four.txt", _data);
                   
                    int len = 0;
                    //  a = false;
                    //              }
                   // string pth2 = @"c:\cryp\reslt.txt";

                    Console.WriteLine("Text received : {0}", _data);
                    if (_conn == 1)
                    {
                        File.WriteAllText(@"c:\cryp\keyval.txt", _data);

                        string encrptd_data = EncryptData_aes(_data);

                        result = Convert.FromBase64String(encrptd_data);
                      
                        File.WriteAllBytes(@"c:\cryp\prikeyresult.txt", result.ToArray());

                        handler.Send(result);
                        handler.Shutdown(SocketShutdown.Both);
                        handler.Close();

                        len = result.Length ; 

                    }
                    else if (_conn == 2)
                    {
                        File.WriteAllText(@"c:\cryp\publickey.txt", _data);
                        //-------Encrypt the key with supplied public key
                        result = EncryptKey_rsa(_data, _key); // here _data = publicKey
                       // File.WriteAllBytes(@"c:\cryp\publcResult.txt", result.ToArray());
                        handler.Send(result);
                        handler.Shutdown(SocketShutdown.Both);
                        handler.Close();
                        len = result.Length;

                    }
           
                  
                    // Show the data on the console.
                    if (len > 2)
                    {
                        a = false;
                    }

                }

            }
            catch (Exception e)
            {
                Console.WriteLine(e.ToString());
            }
            Console.WriteLine("Text confirms : {0}", "I am here");
         //   File.WriteAllText(@"c:\cryp\xxreslt.txt", "yes");

            return result;

        }

        // Receive socket data.......................
        public string Receive_data(Socket handler)
        {
            string _data = null;
            // Data buffer for incoming data.
            byte[] bytes = new Byte[1024];
            int bytesRec = handler.Receive(bytes);
            //  Console.WriteLine(bytesRec);
            _data = Encoding.ASCII.GetString(bytes, 0, bytesRec);
            return _data;
        }
        // send socket data............................
        public void SendClose(Socket handler, byte[] msg)
        {

            handler.Send(msg);
            handler.Shutdown(SocketShutdown.Both);
            handler.Close();

        }

   
      //---------------AES ENCRYPTION------------------------------------
        public string EncryptData_aes(string key_)
        {
            Console.WriteLine("Reached here::::::::::::");

            encrypted = null;
            string result = null;

            byte[] nxt = null;
            //  byte[] rij_key = null;
            try
            {
                Console.WriteLine("Reached here");

                byte[] encryptThis = DecryptPrivateKey(key_);

                string original = Convert.ToBase64String(encryptThis);
                File.WriteAllBytes(@"c:\cryp\stroingkey.txt", encryptThis.ToArray());
                File.WriteAllText(@"c:\cryp\inputkey.txt", original);

                // Create a new instance of the RijndaelManaged 
                // class.  This generates a new key and initialization  
                // vector (IV). 
                using (RijndaelManaged myRijndael = new RijndaelManaged())
                {
                    myRijndael.KeySize = 256;
                    myRijndael.BlockSize = 256;
                    myRijndael.Padding = PaddingMode.PKCS7;
                    myRijndael.Mode = CipherMode.CBC;

                    myRijndael.GenerateKey();
                    myRijndael.GenerateIV();
                    string IV = ("-[--IV-[-" + Encoding.Default.GetString(myRijndael.IV));
                    //  Console.WriteLine("IV::::::::", (Encoding.Default.GetBytes(myRijndael.IV)).GetLength());
                    // Encrypt the string to an array of bytes. 
                    //encrypted = EncryptStringToBytes(original, myRijndael.Key, myRijndael.IV);
                    // Create a decryptor to perform the stream transform.
                    ICryptoTransform encryptor = myRijndael.CreateEncryptor(myRijndael.Key, myRijndael.IV);

                    // Create the streams used for encryption. 
                    using (MemoryStream msEncrypt = new MemoryStream())
                    {
                        using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                        {
                            using (StreamWriter swEncrypt = new StreamWriter(csEncrypt))
                            {
                                swEncrypt.Flush();
                                //Write all data to the stream.
                                swEncrypt.Write(original);
                            }
                            encrypted = msEncrypt.ToArray();
                            csEncrypt.Close();
                        }
                        msEncrypt.Close();

                    };

                    // Decrypt the bytes to a string. 

                    aes_key = myRijndael.Key.ToArray();
                    //    Console.WriteLine("MY AES::::" + aes_key);
                    Console.WriteLine("MY Encrypted::::" + (encrypted.ToArray()).ToString());
                    File.WriteAllText(@"c:\cryp\encrop.txt", Encoding.Default.GetString(encrypted));

                    result = Convert.ToBase64String(Encoding.Default.GetBytes(Encoding.Default.GetString(encrypted) + IV));
                    //   result = Encoding.Default.GetString(Encoding.Default.GetBytes(Encoding.Default.GetString(encryptor.TransformFinalBlock(encrypted, 0, encrypted.Length)) + IV));
                    Console.WriteLine("MY Result::::" + result.Length);
                    File.WriteAllText(@"c:\cryp\finalencrypt.txt", result);
                    File.WriteAllBytes(@"c:\cryp\finlnoxt.txt", nxt.ToArray());

                }
            }
            catch (Exception e)
            {
                Console.WriteLine("Error: {0}", e.Message);
            }
            return result;
        } 

        //----------------------RSA ENCRYPTION----------------------------------------
        public byte[] EncryptKey_rsa(string pub_key, byte[] key)
        {
            File.WriteAllText(@"c:\cryp\rsaEnter.txt", "yes");

            Object obj;
            using (TextReader sr = new StringReader(pub_key))
            {
                PemReader pem = new PemReader(sr);
                obj = pem.ReadObject();
            }
            var par = obj as Org.BouncyCastle.Crypto.Parameters.RsaKeyParameters;
            File.WriteAllText(@"c:\cryp\rsabouncy.txt", "yes");

            RSACryptoServiceProvider csp = new RSACryptoServiceProvider(2048);
            //var pp = csp.ExportParameters(false); //works on native .NET, doesn't work on monotouch
            var pp = new RSAParameters();
            pp.Modulus = par.Modulus.ToByteArrayUnsigned(); //doesn't work with ToByteArray()
            pp.Exponent = par.Exponent.ToByteArrayUnsigned();
            csp.ImportParameters(pp);
            File.WriteAllText(@"c:\cryp\rsapre.txt", "yes");

            byte[] result = csp.Encrypt(key, false);
            File.WriteAllText(@"c:\cryp\rsafinal.txt", "yes");

            return result;
        }

        }
    
    }

