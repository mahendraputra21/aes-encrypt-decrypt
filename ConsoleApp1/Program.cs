using System.Text;
using System.Security.Cryptography;
using Encrypted_lib;

var message = "This is my secret message...!";
var password = EncryptionHelpers.GenerateSecurePassword(32);

// Create sha256 hash
var mySHA256 = SHA256.Create();
byte[] key = mySHA256.ComputeHash(Encoding.ASCII.GetBytes(password));

// Create secret IV
byte[] iv = new byte[16] { 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0 };

var encrypted = EncryptionHelpers.EncryptString(message, key, iv);
var decrypted = EncryptionHelpers.DecryptString(encrypted, key, iv);

Console.WriteLine("Message: " + message);
Console.WriteLine("Password: " + password);
Console.WriteLine("-------------------------------");
Console.WriteLine("Encrypt String: " + encrypted);
Console.WriteLine("Decrypt String: " + decrypted);

Console.ReadKey();
