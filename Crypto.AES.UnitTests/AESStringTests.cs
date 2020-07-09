using System;
using System.Linq;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Crypto.AES.UnitTests
{
    [TestClass]
    public class AESStringTests
    {
        private readonly string key = "ThisKeyMust16Ch";
        private readonly string shortKey = "SHortKEy";

        [TestMethod]
        public void EmptyString()
        {
            using (AES aes = new AES(key))
            {
                Assert.ThrowsException<ArgumentException>(() => aes.Encrypt(stringInput: null));
                Assert.ThrowsException<ArgumentException>(() => aes.Encrypt(stringInput: ""));
                Assert.ThrowsException<ArgumentException>(() => aes.Encrypt(stringInput: " "));

                Assert.ThrowsException<ArgumentException>(() => aes.Decrypt(stringInput: null));
                Assert.ThrowsException<ArgumentException>(() => aes.Decrypt(stringInput: ""));
                Assert.ThrowsException<ArgumentException>(() => aes.Decrypt(stringInput: " "));
            }
        }

        [TestMethod]
        public void Encryption()
        {
            using (AES aes = new AES(key))
                Assert.IsFalse(string.IsNullOrEmpty(aes.Encrypt("asd")));
        }

        [TestMethod]
        public void EncryptionWithShortKey()
        {
            using (AES aes = new AES(shortKey))
                Assert.IsFalse(string.IsNullOrEmpty(aes.Encrypt("asd")));
        }

        [TestMethod]
        public void StaticEncryptionWithShortKey()
        {
            Assert.IsFalse(string.IsNullOrEmpty(AES.EncryptString(shortKey, "asd")));
        }

        [TestMethod]
        public void Decryption() {
            using (AES aes = new AES(key))
            {
                string toBeEncrypted = "test";
                string encrypted = aes.Encrypt(toBeEncrypted);
                string decrypted = aes.Decrypt(encrypted);
                Assert.AreEqual(toBeEncrypted, decrypted);
            }
        }

        [TestMethod]
        public void DecryptionWithShortKey()
        {
            using (AES aes = new AES(shortKey))
            {
                string toBeEncrypted = "test";
                string encrypted = aes.Encrypt(toBeEncrypted);
                string decrypted = aes.Decrypt(encrypted);
                Assert.AreEqual(toBeEncrypted, decrypted);
            }
        }

        [TestMethod]
        public void StaticDecryptionWithShortKey()
        {
            string toBeEncrypted = "test";
            string encrypted = AES.EncryptString(shortKey, toBeEncrypted);
            string decrypted = AES.DecryptString(shortKey, encrypted);
            Assert.AreEqual(toBeEncrypted, decrypted);
        }

        [TestMethod]
        public void RandomKeyLength()
        {
            string longKey = "ThisIsALongKeyIsntIt";

            for (int i = 0; i < 100; i++)
            {
                string textToEncrypt = RandomString(64);
                for (int j = 1; j < 18; j++)
                {
                    string key = longKey.Substring(0, j);
                    using (AES aes = new AES(key))
                    {
                        string encrypted = aes.Encrypt(textToEncrypt);
                        string decrypted = aes.Decrypt(encrypted);

                        if (textToEncrypt != decrypted)
                        {
                            Assert.Fail();
                        }

                        Assert.AreEqual(textToEncrypt, decrypted);
                    }
                }
            }
        }

        private string RandomString(int length)
        {
            Random random = new Random();
            const string chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
            return new string(Enumerable.Repeat(chars, length)
              .Select(s => s[random.Next(s.Length)]).ToArray());
        }
    }
}
