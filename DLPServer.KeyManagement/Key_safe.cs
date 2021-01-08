using DLPServer.Domain.Models;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.IO;
using System.Runtime.InteropServices;
using System.Threading.Tasks;


namespace DLPServer.KeyManagement
{
    class Key_safe
    {
                int success = 0;

        /// <summary>
        /// Call the Unmanaged code With Platform Invoke method.This method is responsible for encrypting
        /// KeySafe
        /// </summary>
        /// <param name="oPrivKey">Private Key</param>
        /// <param name="oPubKey">Public key</param>
        /// <param name="retPrKeyLen">Lenght of private key</param>
        /// <param name="retPubKeyLen">Length of public key</param>
        /// <returns></returns>
        [DllImport("GWECrypto.dll", CallingConvention = CallingConvention.Cdecl)]
        private static extern unsafe int encKeySafe(
            byte[] iKeySafe,
            uint KeysafeLen,
            byte** oBuffer,
            ref ulong retLen,
            byte[] CEOPubKey,
            byte[] AuditorPubKey,
            byte[] EsafePubKey,
            uint CEOKeyLen,
            uint AuditorKeyLen,
            uint EsafeKeyLen
            );

        /// <summary>
        /// Call the Unmanaged code With Platform Invoke method.This method is responsible for decrypting
        /// KeySafe
        /// </summary>
        /// <param name="oPrivKey">Private Key</param>
        /// <param name="oPubKey">Public key</param>
        /// <param name="retPrKeyLen">Lenght of private key</param>
        /// <param name="retPubKeyLen">Length of public key</param>
        /// <returns></returns>
        [DllImport("GWECrypto.dll", CallingConvention = CallingConvention.Cdecl)]
        private static extern unsafe int decKeySafe(
            byte[] eKeySafe,
            uint KeysafeLen,
            byte** oBuffer,
            ref ulong retLen,
            byte[] theKey,
            uint theKeyLen
            );

        /// <summary>
        /// Call the Unmanaged code With Platform Invoke method.This method is responsible for encrypting
        /// KeySafe
        /// </summary>
        /// <param name="oPrivKey">Private Key</param>
        /// <param name="oPubKey">Public key</param>
        /// <param name="retPrKeyLen">Lenght of private key</param>
        /// <param name="retPubKeyLen">Length of public key</param>
        /// <returns></returns>
        [DllImport("GWECrypto.dll", CallingConvention = CallingConvention.Cdecl)]
        private static extern unsafe int encVal(
            byte[] plain,
            uint length,
            byte[] pass,
            byte** oCipher,
            ref ulong cipherLen
            );

        /// <summary>
        /// Call the Unmanaged code With Platform Invoke method.This method is responsible for decrypting
        /// keys with provided password
        /// </summary>
        /// <param name="oPrivKey">Private Key</param>
        /// <param name="oPubKey">Public key</param>
        /// <param name="retPrKeyLen">Lenght of private key</param>
        /// <param name="retPubKeyLen">Length of public key</param>
        /// <returns></returns>
        [DllImport("GWECrypto.dll", CallingConvention = CallingConvention.Cdecl)]
        private static extern unsafe int decVal(
            byte[] cipher,
            uint len,
            byte[] pass,
            byte** oPlain,
            ref ulong plainLen
            );

        /// <summary>
        ///  Call the Unmanaged code With Platform Invoke method.This method is responsible for encrypting
        /// the private key with KeySafe public key
        /// </summary>
        /// <param name="iBuf">user/usergoup private key</param>
        /// <param name="length">user/usergoup private key length</param>
        /// <param name="pubKey">Key safe public Key</param>
        /// <param name="pubKeyLen">Key safe public Key length</param>
        /// <param name="oBuf">encrypted key</param>
        /// <param name="oRetLen">encrypted key length</param>
        /// <returns></returns>
        [DllImport("GWECrypto.dll", CallingConvention = CallingConvention.Cdecl)]
        private static extern unsafe int encValRSA(
            byte[] iBuf,
            uint length,
            byte[] pubKey,
            uint pubKeyLen,
            byte** oBuf,
            ref ulong oRetLen
            );
        /// <summary>
        /// Call the Unmanaged code With Platform Invoke method.This method is responsible for decrypting
        /// the private key with KeySafe private key
        /// </summary>
        /// <param name="iBuf">user/usergeroup encrypted key</param>
        /// <param name="length">user/usergeroup encrypted key length</param>
        /// <param name="privKey">keysafe private key</param>
        /// <param name="privKeyLen">keysafe private key length</param>
        /// <param name="oBuf">decrypted key</param>
        /// <param name="oRetLen">decrypted key length</param>
        /// <returns></returns>
        [DllImport("GWECrypto.dll", CallingConvention = CallingConvention.Cdecl)]
        private static extern unsafe int decValRSA(
            byte[] iBuf,
            uint length,
            byte[] privKey,
            uint privKeyLen,
            byte** oBuf,
            ref ulong oRetLen
            );

        /// <summary>
        /// Encrypt the keySafe key system to generate a master key for decrypting all generated keys
        /// </summary>
        /// <param name="keySafePair"></param>
        /// <param name="CEOKeyPair"></param>
        /// <param name="AuditorKeyPair"></param>
        /// <param name="eSafeKeyPair"></param>
        public unsafe void EncryptKeySafe(KeyPair keySafePair, KeyPair CEOKeyPair, KeyPair AuditorKeyPair, KeyPair eSafeKeyPair)
        {
            byte* encryptedKeysafe = null;
            ulong encryptedKeyLength = ulong.MinValue;

            uint keySafePrivateKeyLength = uint.Parse(keySafePair.PrivateKeyByte.LongLength.ToString());

            uint CEOPublicKeyLength = uint.Parse(CEOKeyPair.PublickKeyByte.LongLength.ToString());
            uint AuditorPublicKeyLength = uint.Parse(AuditorKeyPair.PublickKeyByte.LongLength.ToString());
            uint eSafePublicKeyLength = uint.Parse(eSafeKeyPair.PublickKeyByte.LongLength.ToString());


            try
            {
                unsafe
                {
                    int success = encKeySafe(keySafePair.PrivateKeyByte, keySafePrivateKeyLength, &encryptedKeysafe, ref encryptedKeyLength,
                                  CEOKeyPair.PublickKeyByte, AuditorKeyPair.PublickKeyByte, eSafeKeyPair.PublickKeyByte, CEOPublicKeyLength,
                                  AuditorPublicKeyLength, eSafePublicKeyLength);

                }
                if (encryptedKeysafe != null && encryptedKeyLength != ulong.MinValue)
                {
                    byte[] encryptedKey = new byte[encryptedKeyLength];
                    for (ulong i = 0; i < encryptedKeyLength; i++)
                    {
                        encryptedKey[i] = encryptedKeysafe[i];
                    }
                    EncryptedKey = encryptedKey;
                }
                else
                {
                    EncryptedKey = null;
                }
            }

            catch (Exception ex)
            {

            }
        }


        /// <summary>
        /// Decrypt the key with one of the CEO/Auditor/eSafe keys
        /// </summary>
        /// <param name="KeySafePair">KeySafe System</param>
        /// <param name="decryptor">CEO/Auditor/eSafe</param>
        public unsafe byte[] DecryptKeySafe(KeyPair KeySafePair, KeyPair decryptor)
        {
             File.WriteAllText(@"c:\cryp\apple.txt", "yes!! it entered the function");

            byte* decryptedKey = null;
            ulong decryptedKeyLength = ulong.MinValue;

            uint keySafePrivateKeyLength = uint.Parse(KeySafePair.PrivateKeyByte.LongLength.ToString());
            uint decryptorLength = uint.Parse(decryptor.PrivateKeyByte.LongLength.ToString());
            File.WriteAllText(@"c:\cryp\not1.txt", "yes!! OK DONJW");

            try
            {
                unsafe
                {
                    int success = decKeySafe(KeySafePair.PrivateKeyByte, keySafePrivateKeyLength, &decryptedKey, ref decryptedKeyLength,
                        decryptor.PrivateKeyByte, decryptorLength);
              //      File.WriteAllText(@"c:\cryp\notsucess.txt","val::"+success);

                }
                if (decryptedKey != null && decryptedKeyLength != ulong.MinValue)
                {
                    byte[] decryptedBytes = new byte[decryptedKeyLength];
                    for (ulong i = 0; i < decryptedKeyLength; i++)
                    {
                        decryptedBytes[i] = decryptedKey[i];
                    }
                    DecryptedKey = decryptedBytes;
                    return DecryptedKey;
                }
                else
                {
                    DecryptedKey = null;
                    return DecryptedKey;
                }

            }
            catch (Exception ex)
            {

                throw;
            }
        }

        /// <summary>
        /// Encrypt the private/public key pair with the password user provide
        /// </summary>
        /// <param name="keyPair">private/public key pair</param>
        /// <param name="password">MD5 hash password</param>
        public unsafe void EncryptKeyWithPassword(KeyPair keyPair, byte[] password)
        {
            byte* encryptedKey = null;
            ulong encryptedKeyLength = ulong.MinValue;
            uint keyLength = uint.Parse(keyPair.PrivateKeyByte.LongLength.ToString());

            try
            {
                unsafe
                {
                    int success = encVal(keyPair.PrivateKeyByte, keyLength, password, &encryptedKey, ref encryptedKeyLength);
                }
                if (encryptedKey != null && encryptedKeyLength != ulong.MinValue)
                {
                    byte[] encryptedBytes = new byte[encryptedKeyLength];
                    for (ulong i = 0; i < encryptedKeyLength; i++)
                    {
                        encryptedBytes[i] = encryptedKey[i];
                    }
                    EncryptedKey = encryptedBytes;
                }
                else
                {
                    EncryptedKey = null;
                }
            }
            catch (Exception ex)
            {

                throw;
            }
        }
        /// <summary>
        /// Decrypt the private/public key pair with the password user provide
        /// </summary>
        /// <param name="keyPair">private/public key pair</param>
        /// <param name="password">MD5 hash password</param>
        public unsafe byte[] DecryptKeyWithPassword(KeyPair keyPair, byte[] password)
        {
           byte* encryptedKey = null;
            ulong encryptedKeyLength = ulong.MinValue;
            uint keyLength = uint.Parse(keyPair.PrivateKeyByte.LongLength.ToString());

            try
            {
                unsafe
                {
                    success = decVal(keyPair.PrivateKeyByte, keyLength, password, &encryptedKey, ref encryptedKeyLength);
                 //   File.WriteAllText(@"c:\cryp\ret\decryptWpassword.txt", "yes"+success);

                }
                if (encryptedKey != null && encryptedKeyLength != ulong.MinValue && success == 0)
                {
                    byte[] encryptedBytes = new byte[encryptedKeyLength];
                    for (ulong i = 0; i < encryptedKeyLength; i++)
                    {
                        encryptedBytes[i] = encryptedKey[i];
                    }
                    DecryptedKey = encryptedBytes;
                    return DecryptedKey;
                }
                else
                {
                    DecryptedKey = null;
                    return DecryptedKey;
                }

            }
            catch (Exception ex)
            {
                throw;
            }
        }

        public unsafe void EncryptWithKeysafe(KeyPair keyPair, KeyPair keySafe)
        {
            byte* encryptedKey = null;
            ulong encryptedKeyLength = ulong.MinValue;
            uint keyLength = uint.Parse(keyPair.PrivateKeyByte.LongLength.ToString());
            uint keySafeLength = uint.Parse(keySafe.PublickKeyByte.LongLength.ToString());
            try
            {
                unsafe
                {
                    int success = encValRSA(keyPair.PrivateKeyByte, keyLength, keySafe.PublickKeyByte, keySafeLength, &encryptedKey, ref encryptedKeyLength);
                }
                if (encryptedKey != null && encryptedKeyLength != ulong.MinValue)
                {
                    byte[] encryptedBytes = new byte[encryptedKeyLength];
                    for (ulong i = 0; i < encryptedKeyLength; i++)
                    {
                        encryptedBytes[i] = encryptedKey[i];
                    }
                    EncryptedKey = encryptedBytes;
                }
                else
                {
                    EncryptedKey = null;
                }
            }
            catch (Exception ex)
            {

                throw;
            }

        }

        public unsafe void DecryptWithKeysafe(KeyPair keyPair, KeyPair Keysafe)
        {
           // File.WriteAllText(@"c:\cryp\ret\not1.txt", "yes");

            byte* decryptedKey = null;
            ulong decryptedKeyLength = ulong.MinValue;
            uint keyLength = uint.Parse(keyPair.PrivateKeyByte.LongLength.ToString());
            uint keySafeLength = uint.Parse(Keysafe.PrivateKeyByte.LongLength.ToString());
         //   File.WriteAllText(@"c:\cryp\ret\not2.txt", "yes");

            try
            {
                unsafe
                {
//                    File.WriteAllText(@"c:\cryp\ret\not3.txt", "yes");

                    int success = decValRSA(keyPair.PrivateKeyByte, keyLength, Keysafe.PrivateKeyByte, keySafeLength, &decryptedKey, ref decryptedKeyLength);
                }
                if (decryptedKey != null && decryptedKeyLength != ulong.MinValue)
                {
                    byte[] decryptedBytes = new byte[decryptedKeyLength];
                    for (ulong i = 0; i < decryptedKeyLength; i++)
                    {
                        decryptedBytes[i] = decryptedKey[i];
                    }
                    DecryptedKey = decryptedBytes;
//                    File.WriteAllText(@"c:\cryp\ret\not.txt", "yes");

                }
                else
                {
                    DecryptedKey = null;
                 //   File.WriteAllText(@"c:\cryp\ret\fail.txt", "yes");

                }
            }
            catch (Exception ex)
            {

                throw;
            }
        }


        public unsafe void EncryptWithPublic(byte[] blob, byte[] publicKey)
        {
            byte* encryptedKey = null;
            ulong encryptedKeyLength = ulong.MinValue;
            uint blobLength = uint.Parse(blob.LongLength.ToString());
            uint publicKeyLength = uint.Parse(publicKey.LongLength.ToString());
            try
            {
                unsafe
                {
                    int success = encValRSA(blob, blobLength, publicKey, publicKeyLength, &encryptedKey, ref encryptedKeyLength);
                }
                if (encryptedKey != null && encryptedKeyLength != ulong.MinValue)
                {
                    byte[] encryptedBytes = new byte[encryptedKeyLength];
                    for (ulong i = 0; i < encryptedKeyLength; i++)
                    {
                        encryptedBytes[i] = encryptedKey[i];
                    }
                    EncryptedKey = encryptedBytes;
                }
                else
                {
                    EncryptedKey = null;
                }
            }
            catch (Exception ex)
            {

                throw;
            }

        }


        public unsafe byte[] DecryptWithPrivate(byte[] blob, byte[] privateKey)
        {
            byte* decryptedKey = null;
            ulong decryptedKeyLength = ulong.MinValue;
            uint blobLength = uint.Parse(blob.LongLength.ToString());
            uint privateKeyLength = uint.Parse(privateKey.LongLength.ToString());
           // File.WriteAllText(@"c:\cryp\ret\not22.txt", "yes");

            try
            {
                unsafe
                {
                    int success = decValRSA(blob, blobLength, privateKey, privateKeyLength, &decryptedKey, ref decryptedKeyLength);
                }
                if (decryptedKey != null && decryptedKeyLength != ulong.MinValue)
                {
                    byte[] decryptedBytes = new byte[decryptedKeyLength];
                    for (ulong i = 0; i < decryptedKeyLength; i++)
                    {
                        decryptedBytes[i] = decryptedKey[i];
                    }
                    DecryptedKey = decryptedBytes;
//                    File.WriteAllBytes(@"c:\cryp\ret\not28.txt", DecryptedKey);
                    return DecryptedKey;

                }
                else
                {
                    DecryptedKey = null;
                    return DecryptedKey;
                }
            }
            catch (Exception ex)
            {

                throw;
            }
        }


        public byte[] EncryptedKey { get; set; }


        public byte[] DecryptedKey { get; set; }




    }

    }

