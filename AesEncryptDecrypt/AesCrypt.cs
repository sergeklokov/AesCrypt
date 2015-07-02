using System;
using System.Text;
using System.IO;
using System.Security.Cryptography;

namespace AesEncryptDecrypt
{
    /// <summary>
    /// Advanced Encryption Standard (AES) or Rijndael encryption unit
    /// http://en.wikipedia.org/wiki/Advanced_Encryption_Standard
    /// this unit is pretty much a copy/paste & compilation of MSDN & stackoverflow AES examples
    /// </summary>
    public static class AesCrypt
    {
        private const string UrlKeyString = "3451A9B89"; // Must be 8 characters or more
        internal static readonly byte[] UrlkeyBytes = { 0x11, 0x38, 0x15, 0x34, 0x67, 0xA6, 0xB7, 0x4C }; // Must be 8 bytes

        static public string DecryptString(string value, string key)
        {
            return DecryptString(value, key, Encoding.ASCII);
        }

        static public string EncryptString(string value, string key)
        {
            return EncryptString(value, key, Encoding.ASCII);
        }

        static public string EncryptString(string value, string key, Encoding textConverter)
        {
            if (string.IsNullOrEmpty(value)) return string.Empty;

            var rijndael = new RijndaelManaged();

            // get keys
            byte[] bufKey = BuildRijndaelKey(key);
            byte[] bufRinjdaelIV = getRijndaelIV();

            // load the buffers
            byte[] bufDecrypted = textConverter.GetBytes(value);

            // create the encryptors
            ICryptoTransform encryptor = rijndael.CreateEncryptor(bufKey, bufRinjdaelIV);
            var msEncrypt = new MemoryStream();
            byte[] bufEncrypted;
            using(var cryptoStream = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
            {
                // encrypt the buffer
                cryptoStream.Write(bufDecrypted, 0, bufDecrypted.Length);
                cryptoStream.FlushFinalBlock();
                bufEncrypted = msEncrypt.ToArray();
            }

            return Convert.ToBase64String(bufEncrypted);
        }

        static public string DecryptString(string value, string key, Encoding textConverter)
        {
            if (string.IsNullOrEmpty(value)) return string.Empty;

            var rijndael = new RijndaelManaged();

            // get keys
            byte[] bufKey = BuildRijndaelKey(key);
            byte[] bufRinjdaelIV = getRijndaelIV();

            // load the buffers
            byte[] bufEncrypted = Convert.FromBase64String(value);
            byte[] bufDecrypted = new byte[bufEncrypted.Length];

            // create the decryptors
            ICryptoTransform decryptor = rijndael.CreateDecryptor(bufKey, bufRinjdaelIV);
            var msDecrypt = new MemoryStream(bufEncrypted);
            using (var csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
            {

                // decrypt the buffer
                csDecrypt.Read(bufDecrypted, 0, bufDecrypted.Length);
            }
            return textConverter.GetString(bufDecrypted).Replace("\0", "");
        }

        //sometimes we don't know if string is ecrypted or not
        static public bool TryDecryptString(string value, string key, out string decryptedValue)
        {
            var output = false;

            try
            {
                decryptedValue = DecryptString(value, key, Encoding.UTF8);
                output = true;
            }
            catch
            {
                decryptedValue = value;
            }

            return output;
        }

        internal static byte[] BuildRijndaelKey(string value)
        {
            // truncate to a maximum of 32
            if (value.Length > 32)
                value = value.Substring(0, 32);

            // create a default Rinjdael key
            var asciiEncoding = new ASCIIEncoding();
            byte[] bufValue = asciiEncoding.GetBytes(value);
            byte[] bufRijndaelKey = { 0xE4, 0x28, 0xE4, 0x03, 0x56, 0x57, 0x14, 0xDE,0xD4, 0x69, 0x3A, 0x54, 0x66, 0xC0, 0x58, 0xF6,
                                      0xB3, 0x37, 0x3B, 0x05, 0x86, 0x77, 0x61, 0x35,0xD2, 0x25, 0xAF, 0x12, 0xA4, 0x0C, 0x99, 0xCD };

            // replace the default key with the parameter value
            for (var i = 0; i < bufValue.Length; i++)
                bufRijndaelKey[i] = bufValue[i];

            return bufRijndaelKey;

        } 

        internal static byte[] getRijndaelIV()
        {
            byte[] bufRijndaelIV = { 0xED, 0x15, 0xE0, 0x9E, 0xD8, 0xF7, 0x90, 0x9E, 0x48, 0x93, 0x07, 0x7B, 0xA3, 0x8D, 0x6D, 0xA8 };

            return bufRijndaelIV;
        }

        internal static string BuildKey()
        {
            byte[] buf = { 0xE4, 0x28, 0xAA, 0x03, 0x56, 0x57, 0x13, 0xDE,0x3A, 0x22, 0x5E, 0xE0, 0x6B, 0xD5, 0x34, 0x29,
                           0x3B, 0xA3, 0x73, 0xDD, 0x12, 0x27, 0xBA, 0xD8,0xAF, 0x45, 0xCE, 0x27, 0x0D, 0xE0, 0xD3, 0xE3 };

            return EncodeBuffer(buf);
        }

        private static string EncodeBuffer(byte[] buffer)
        {
            var encoding = new ASCIIEncoding();
            return encoding.GetString(buffer);
        }

        /// <summary>
        /// Provides ability to encrypt a URL, or Query string parameter in a format suitable for use in a Uri.
        /// Standard encryption results in some characters (such as '+', or '=') that are not suitable for URL encoding/decoding.
        /// This method provides encryption, but also converts the resulting byte array into HEX characters, which are suitable
        /// for direct use, even without URL Encoding.
        /// 
        /// This method provides the ability to pass secure data within a Query String, and/or enables embedded URL's to be utilized
        /// in script without opening yourself to attacks based on altering query parameters.
        /// </summary>
        /// <param name="text"></param>
        /// <returns></returns>
        static public string EncryptUrl(string text)
        {
            try
            {
                byte[] keyData = Encoding.UTF8.GetBytes(UrlKeyString.Substring(0, 8));
                var des = new DESCryptoServiceProvider();
                byte[] textData = Encoding.UTF8.GetBytes(text);
                
                var ms = new MemoryStream();
                using (var cs = new CryptoStream(ms, des.CreateEncryptor(keyData, UrlkeyBytes), CryptoStreamMode.Write))
                {
                    cs.Write(textData, 0, textData.Length);
                    cs.FlushFinalBlock();
                }

                return ConvertByteArrayToHex(ms.ToArray());
            }
            catch (Exception)
            {
                return String.Empty;
            }
        }

        /// <summary>
        /// Provides ability to DecryptString encrypted hex values created with EncryptUrl().
        /// </summary>
        /// <param name="text"></param>
        /// <returns></returns>
        static public string DecryptUrl(string text)
        {
            try
            {
                byte[] keyData = Encoding.UTF8.GetBytes(UrlKeyString.Substring(0, 8));
                var des = new DESCryptoServiceProvider();
                byte[] textData = ConvertHexToByteArray(text);
                
                var ms = new MemoryStream();
                using (var cs = new CryptoStream(ms, des.CreateDecryptor(keyData, UrlkeyBytes), CryptoStreamMode.Write))
                {
                    cs.Write(textData, 0, textData.Length);
                    cs.FlushFinalBlock();
                }

                return Encoding.UTF8.GetString(ms.ToArray());
            }
            catch (Exception)
            {
                return String.Empty;
            }
        }

        static public string ConvertByteArrayToHex(byte[] data)
        {
            var results = new StringBuilder();

            foreach (byte b in data)
                results.Append(b.ToString("X2"));

            return results.ToString();
        }

        // I have concern if this method works correctly 
        // TODO: test and fix
        static public byte[] ConvertHexToByteArray(string data)
        {
            byte[] results = new byte[data.Length / 2];

            for (int i = 0; i < data.Length; i += 2)
                results[i / 2] = Convert.ToByte(data.Substring(i, 2), 16);

            return results;
        }


        internal const string StringPassword = "uhdweylsvst"; // Change this
        internal static readonly byte[] RgbSalt = { 0x68, 0x34, 0x23, 0x92, 0x59, 0x34, 0x23, 0x45 }; // Change this too

        /// <summary>
        /// Encrypt bytes to bytes
        /// idea taken from here
        /// http://www.splinter.com.au/c-cryptography-encrypting-a-bunch-of-bytes/
        /// </summary>
        /// <param name="input"></param>
        /// <returns></returns>
        public static byte[] EncryptByteArray(byte[] input)
        {
            PasswordDeriveBytes pdb = new PasswordDeriveBytes(StringPassword, RgbSalt);
              
            MemoryStream ms = new MemoryStream();
            Aes aes = new AesManaged();
            aes.Key = pdb.GetBytes(aes.KeySize / 8);
            aes.IV = pdb.GetBytes(aes.BlockSize / 8);
            CryptoStream cs = new CryptoStream(ms, aes.CreateEncryptor(), CryptoStreamMode.Write);
            cs.Write(input, 0, input.Length);
            cs.Close();
            return ms.ToArray();
        }

        /// <summary>
        /// Decrypt bytes to bytes
        /// </summary>
        /// <param name="input"></param>
        /// <returns></returns>
        public static byte[] DecryptByteArray(byte[] input)
        {
            PasswordDeriveBytes pdb = new PasswordDeriveBytes(StringPassword, RgbSalt);

            MemoryStream ms = new MemoryStream();
            Aes aes = new AesManaged();
            aes.Key = pdb.GetBytes(aes.KeySize / 8);
            aes.IV = pdb.GetBytes(aes.BlockSize / 8);
            CryptoStream cs = new CryptoStream(ms, aes.CreateDecryptor(), CryptoStreamMode.Write);
            cs.Write(input, 0, input.Length);
            cs.Close();
            return ms.ToArray();
        }

        public static string EncryptStringToString(string input)
        {
            return Convert.ToBase64String(EncryptByteArray(Encoding.UTF8.GetBytes(input)));
        }

        public static string DecryptStringToString(string input)
        {
            return Encoding.UTF8.GetString(DecryptByteArray(Convert.FromBase64String(input)));
        }

        public static byte[] GetBytesFromString(string str)
        {
            byte[] bytes = new byte[str.Length * sizeof(char)];
            System.Buffer.BlockCopy(str.ToCharArray(), 0, bytes, 0, bytes.Length);
            return bytes;
        }

        public static string GetStringFromBytes(byte[] bytes)
        {
            char[] chars = new char[bytes.Length / sizeof(char)];
            System.Buffer.BlockCopy(bytes, 0, chars, 0, bytes.Length);
            return new string(chars);
        }
    } 

} 


