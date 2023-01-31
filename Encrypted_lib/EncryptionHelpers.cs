using System.Security.Cryptography;
using System.Text;

namespace Encrypted_lib
{
    public class EncryptionHelpers
    {
        public static string EncryptString(string plainText, byte[] key, byte[] iv)
        {
            // Create a new AES object for encryption
            using Aes encryptor = Aes.Create();

            // Set the encryption mode to CBC
            encryptor.Mode = CipherMode.CBC;

            // Use the first 32 bytes of the key
            encryptor.Key = key.Take(32).ToArray();

            // Set the initialization vector
            encryptor.IV = iv;

            // Create a memory stream to store the encrypted data
            using var memoryStream = new MemoryStream();

            // Create an encryptor from the AES object
            using var aesEncryptor = encryptor.CreateEncryptor();

            // Use the encryptor with a crypto stream to encrypt the data
            using var cryptoStream = new CryptoStream(memoryStream, aesEncryptor, CryptoStreamMode.Write);

            // Convert the plain text to a byte array
            byte[] plainBytes = Encoding.ASCII.GetBytes(plainText);

            // Write the plain bytes to the crypto stream to be encrypted
            cryptoStream.Write(plainBytes, 0, plainBytes.Length);

            // Flush the final block of data to the memory stream
            cryptoStream.FlushFinalBlock();

            // Convert the encrypted data in the memory stream to a byte array
            byte[] cipherBytes = memoryStream.ToArray();

            // Convert the encrypted byte array to a base64 encoded string and return it
            return Convert.ToBase64String(cipherBytes);
        }
        public static string DecryptString(string cipherText, byte[] key, byte[] iv)
        {
            // Instantiate a new Aes object to perform string symmetric encryption
            Aes encryptor = Aes.Create();

            encryptor.Mode = CipherMode.CBC;

            // Set key and IV
            byte[] aesKey = new byte[32];
            Array.Copy(key, 0, aesKey, 0, 32);
            encryptor.Key = aesKey;
            encryptor.IV = iv;

            // Instantiate a new MemoryStream object to contain the encrypted bytes
            MemoryStream memoryStream = new MemoryStream();

            // Instantiate a new encryptor from our Aes object
            ICryptoTransform aesDecryptor = encryptor.CreateDecryptor();

            // Instantiate a new CryptoStream object to process the data and write it to the 
            // memory stream
            CryptoStream cryptoStream = new CryptoStream(memoryStream, aesDecryptor, CryptoStreamMode.Write);

            // Will contain decrypted plaintext
            string plainText = String.Empty;

            try
            {
                // Convert the ciphertext string into a byte array
                byte[] cipherBytes = Convert.FromBase64String(cipherText);

                // Decrypt the input ciphertext string
                cryptoStream.Write(cipherBytes, 0, cipherBytes.Length);

                // Complete the decryption process
                cryptoStream.FlushFinalBlock();

                // Convert the decrypted data from a MemoryStream to a byte array
                byte[] plainBytes = memoryStream.ToArray();

                // Convert the decrypted byte array to string
                plainText = Encoding.ASCII.GetString(plainBytes, 0, plainBytes.Length);
            }
            finally
            {
                // Close both the MemoryStream and the CryptoStream
                memoryStream.Close();
                cryptoStream.Close();
            }

            // Return the decrypted data as a string
            return plainText;
        }
        public static string GenerateSecurePassword(int length)
        {
            // The set of characters to use in the password
            const string characters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+-=[]{}|;':\"<>,.?/\\";

            // An array to hold the generated random bytes
            byte[] randomBytes = new byte[length];

            // Use the RNGCryptoServiceProvider to generate the random bytes
            using (var rng = new RNGCryptoServiceProvider())
            {
                rng.GetBytes(randomBytes);
            }

            // An array to hold the password characters
            char[] password = new char[length];

            // Loop through each byte and select a character based on its value
            for (int i = 0; i < length; i++)
            {
                password[i] = characters[randomBytes[i] % characters.Length];
            }

            // Return the password as a string
            return new string(password);
        }
    }
}