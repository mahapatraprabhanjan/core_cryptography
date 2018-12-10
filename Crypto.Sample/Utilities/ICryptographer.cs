namespace Crypto.Sample.Utilities
{
    public interface ICryptographer
    {
        string CreateSalt();

        string Encrypt(string plainText, string salt);

        string Decrypt(string cipherText, string salt);
    }
}
