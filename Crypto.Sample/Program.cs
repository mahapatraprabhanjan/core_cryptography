using Crypto.Sample.Utilities;
using static System.Console;

namespace Crypto.Sample
{
    class Program
    {
        static void Main(string[] args)
        {
            ICryptographer cryptographer = new Cryptographer();
            var rawString = "Hello World";

            var salt = cryptographer.CreateSalt();
            var encryptedString = cryptographer.Encrypt(rawString, salt);

            WriteLine($"Encrypted String - {encryptedString}");
            WriteLine();

            var decryptedString = cryptographer.Decrypt(encryptedString, salt);
            WriteLine($"Decrypted String - {decryptedString}");
            WriteLine();


            ReadLine();
        }
    }
}
