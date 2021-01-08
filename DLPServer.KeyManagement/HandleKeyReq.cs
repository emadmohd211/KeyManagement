using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.IO;
using System.Threading;

namespace DLPServer.KeyManagement
{
    class HandleKeyReq
    {
        //declare and initialize variables..........................
        public string newfile{ get; set; }
        public string file_res { get; set; }
        public string file_pub { get; set; }
        public string pathString { get; set; }
        public string mydocpath { get; set; }
        public string pathString1 { get; set; }
        public string pathString2 { get; set; }
       
        public string myretpath { get; set; }

        // based on the name creates the files.........................
        public void create_file(string filename)
        {
            newfile = filename;

            string[] separatingPt = { "." };

            string[] words = newfile.Split(separatingPt, StringSplitOptions.RemoveEmptyEntries);
            file_res = words[0] + "_res.txt";
            file_pub = words[0] + "_pub.crt";
            pathString = System.IO.Path.Combine(mydocpath, newfile);
            pathString1 = System.IO.Path.Combine(myretpath, file_res);
            pathString2 = System.IO.Path.Combine(myretpath, file_pub);
           


        }
        // reads the files......................................................
        public string read_file(string pString)
        {
            string line = "";
            FileStream iStream = new FileStream(pString, FileMode.Open, FileAccess.Read, FileShare.None);
            using (StreamReader sr = new StreamReader(iStream))
            {
                // Read the stream to a string, and write the string to the console.
                line = sr.ReadToEnd();
            }
            Console.WriteLine(line);

            string result = line;

            File.Delete(pString);
            return result;
        }

        //writes to files.............................................................
        public void write_toFile(byte[] result)
        {
           // result += "!From server";
          /*  FileStream oStream = new FileStream(pathString1, FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None);
            using (StreamWriter outputFile = new StreamWriter(oStream))
            {
                outputFile.WriteLine(result);
            }
            */
            File.WriteAllBytes(pathString1, result);
        }
        public void write_pub(byte[] result)
        {
            File.WriteAllBytes(pathString2, result);
        }


    }
}
