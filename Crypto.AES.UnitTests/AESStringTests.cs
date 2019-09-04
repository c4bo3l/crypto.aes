using System;
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
    }
}
