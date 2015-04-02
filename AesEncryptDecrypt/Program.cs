using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace AesEncryptDecrypt
{
    class Program
    {
        static void Main(string[] args)
        {
            string text = "6E94F7D1-738A-44CF-8971-9FF9403F777C";
            Console.WriteLine("Original text: " + text);
            string encryptedText;

            //encrypt
            using (Aes.Create())
            {
                encryptedText = AesCrypt.EncryptString(text, AesCrypt.BuildKey());
            }
            Console.WriteLine();
            Console.WriteLine("Encrypted text: " + encryptedText);
            Console.WriteLine();

            //decrypt
            string decrypted;

            using (Aes.Create())
            {
                decrypted = AesCrypt.DecryptString(encryptedText, AesCrypt.BuildKey());
            }
            Console.WriteLine("Decrypted text: " + decrypted);

            Console.WriteLine();

            string url = "http://stackoverflow.com/questions/6361176/encrypting-a-string-to-a-url-in-c-sharp";
            Console.WriteLine("Original url: " + url);
            string encryptedUrl;
            using (Aes.Create())
            {
                encryptedUrl = AesCrypt.EncryptUrl(url);
            }
            Console.WriteLine();
            Console.WriteLine("Encrypted url: " + encryptedUrl);
            Console.WriteLine();

            string decryptedUrl;
            using (Aes.Create())
            {
                decryptedUrl = AesCrypt.DecryptUrl(encryptedUrl);
            }
            Console.WriteLine("Decrypted url: " + decryptedUrl);
            
            Console.ReadLine();
        }

    }
}
