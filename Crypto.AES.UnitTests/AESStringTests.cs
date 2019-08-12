using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Crypto.AES.UnitTests
{
    [TestClass]
    public class AESStringTests
    {
        private readonly string key = "ThisKeyMust16Ch";

        [TestMethod]
        public void Encryption()
        {
            using (AES aes = new AES(key))
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
    }
}
