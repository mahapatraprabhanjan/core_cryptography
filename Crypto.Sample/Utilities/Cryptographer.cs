using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace Crypto.Sample.Utilities
{
    public class Cryptographer : ICryptographer
    {
        private static string secretSalt = "1E139818A1F24F97989DF37640A32D0C";

        public string CreateSalt()
        {
            var rng = new RNGCryptoServiceProvider();
            var buff = new byte[256];
            rng.GetNonZeroBytes(buff);

            return Convert.ToBase64String(buff);
        }

        public string Decrypt(string cipherText, string salt)
        {
            if (string.IsNullOrWhiteSpace(cipherText))
            {
                throw new ArgumentNullException(nameof(cipherText));
            }

            if (string.IsNullOrWhiteSpace(salt))
            {
                throw new ArgumentNullException(nameof(salt));
            }

            RijndaelManaged rijndaelManaged = null;

            try
            {
                var sharedSecret = Encoding.UTF8.GetBytes(secretSalt);
                Rfc2898DeriveBytes key = new Rfc2898DeriveBytes(salt, sharedSecret);

                var bytes = Convert.FromBase64String(cipherText);
                using (var memoryStream = new MemoryStream(bytes))
                {
                    rijndaelManaged = new RijndaelManaged();
                    rijndaelManaged.Key = key.GetBytes(rijndaelManaged.KeySize / 8);

                    rijndaelManaged.IV = ReadByteArray(memoryStream);

                    ICryptoTransform decryptor = rijndaelManaged.CreateDecryptor(rijndaelManaged.Key, rijndaelManaged.IV);
                    using (var cryptoStream = new CryptoStream(memoryStream, decryptor, CryptoStreamMode.Read))
                    {
                        using (var stream = new StreamReader(cryptoStream))
                        {
                            return stream.ReadToEnd();
                        }
                    }
                }
            }
            finally
            {
                if (rijndaelManaged != null)
                {
                    rijndaelManaged.Clear();
                }
            }
        }

        public string Encrypt(string plainText, string salt)
        {
            if (string.IsNullOrWhiteSpace(plainText))
            {
                throw new ArgumentNullException(nameof(plainText));
            }

            if (string.IsNullOrWhiteSpace(salt))
            {
                throw new ArgumentNullException(nameof(salt));
            }

            RijndaelManaged rijndael = null;

            try
            {
                var sharedSecret = Encoding.UTF8.GetBytes(secretSalt);
                Rfc2898DeriveBytes key = new Rfc2898DeriveBytes(salt, sharedSecret);

                rijndael = new RijndaelManaged();
                rijndael.Key = key.GetBytes(rijndael.KeySize / 8);

                ICryptoTransform encryptor = rijndael.CreateEncryptor(rijndael.Key, rijndael.IV);

                using (var memoryStream = new MemoryStream())
                {
                    memoryStream.Write(BitConverter.GetBytes(rijndael.IV.Length), 0, sizeof(int));
                    memoryStream.Write(rijndael.IV, 0, rijndael.IV.Length);
                    using (CryptoStream cryptoStream = new CryptoStream(memoryStream, encryptor, CryptoStreamMode.Write))
                    {
                        using (var streamWriter = new StreamWriter(cryptoStream))
                        {
                            streamWriter.Write(plainText);
                        }
                    }

                    return Convert.ToBase64String(memoryStream.ToArray());
                }
            }
            finally
            {
                if (rijndael != null)
                {
                    rijndael.Clear();
                }
            }
        }

        private static byte[] ReadByteArray(Stream stream)
        {
            var rawLength = new byte[sizeof(int)];
            if (stream.Read(rawLength, 0, rawLength.Length) != rawLength.Length)
            {
                throw new SystemException("Stream did not contain properly formatted byte array.");
            }

            var buffer = new byte[BitConverter.ToInt32(rawLength, 0)];
            if(stream.Read(buffer,0, buffer.Length) !=buffer.Length)
            {
                throw new SystemException("Did not read byte array properly.");
            }

            return buffer;
        }
    }
}
