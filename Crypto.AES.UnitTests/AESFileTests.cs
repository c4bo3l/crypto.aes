using System;
using System.IO;
using System.Threading.Tasks;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Crypto.AES.UnitTests
{
    [TestClass]
    public class AESFileTests
    {
        private readonly string key = "ThisKeyMust16Ch";
        private readonly string shortKey = "SHortKEy";
        private readonly string sourceFile = "./ToBeEncryptedFile.txt";
        private readonly string targetEncryptedFile = "./encryptedFile.txt";
        private readonly string targetDecryptedFile = "./decryptedFile.txt";
        private readonly string content = "This is a text.";

        [TestMethod]
        public void EmptySourceFile()
        {
            using (AES aes = new AES(key))
            {
                Assert.ThrowsException<ArgumentException>(() => aes.Encrypt(null, targetEncryptedFile));
                Assert.ThrowsException<ArgumentException>(() => aes.Encrypt("", targetEncryptedFile));
                Assert.ThrowsException<ArgumentException>(() => aes.Encrypt(" ", targetEncryptedFile));

                Assert.ThrowsException<ArgumentException>(() => aes.Decrypt(null, targetEncryptedFile));
                Assert.ThrowsException<ArgumentException>(() => aes.Decrypt("", targetEncryptedFile));
                Assert.ThrowsException<ArgumentException>(() => aes.Decrypt(" ", targetEncryptedFile));
            }
        }

        [TestMethod]
        public void EmptyTargetFile()
        {
            using (AES aes = new AES(key))
            {
                Assert.ThrowsException<ArgumentException>(() => aes.Encrypt(targetEncryptedFile, null));
                Assert.ThrowsException<ArgumentException>(() => aes.Encrypt(targetEncryptedFile, ""));
                Assert.ThrowsException<ArgumentException>(() => aes.Encrypt(targetEncryptedFile, " "));

                Assert.ThrowsException<ArgumentException>(() => aes.Decrypt(targetEncryptedFile, null));
                Assert.ThrowsException<ArgumentException>(() => aes.Decrypt(targetEncryptedFile, ""));
                Assert.ThrowsException<ArgumentException>(() => aes.Decrypt(targetEncryptedFile, " "));
            }
        }

        [TestMethod]
        public async Task EncryptionAsync()
        {
            using (AES aes = new AES(key))
            {
                if (File.Exists(sourceFile))
                    File.Delete(sourceFile);
                File.WriteAllText(sourceFile, content);

                FileInfo encryptedFile = aes.Encrypt(sourceFile, targetEncryptedFile);
                Assert.IsNotNull(encryptedFile);
                Assert.IsTrue(File.Exists(targetEncryptedFile));
                Assert.AreNotEqual
                    (await File.ReadAllTextAsync(targetEncryptedFile), content);
            }
        }

        [TestMethod]
        public async Task EncryptionWithShortKeyAsync()
        {
            using (AES aes = new AES(shortKey))
            {
                if (File.Exists(sourceFile))
                    File.Delete(sourceFile);
                File.WriteAllText(sourceFile, content);

                FileInfo encryptedFile = aes.Encrypt(sourceFile, targetEncryptedFile);
                Assert.IsNotNull(encryptedFile);
                Assert.IsTrue(File.Exists(targetEncryptedFile));
                Assert.AreNotEqual
                    (await File.ReadAllTextAsync(targetEncryptedFile), content);
            }
        }

        [TestMethod]
        public async Task DecryptionAsync()
        {
            using (AES aes = new AES(key))
            {
                if (File.Exists(sourceFile))
                    File.Delete(sourceFile);
                File.WriteAllText(sourceFile, content);

                FileInfo encryptedFile = aes.Encrypt(sourceFile, targetEncryptedFile);
                Assert.IsNotNull(encryptedFile);
                Assert.IsTrue(File.Exists(targetEncryptedFile));

                FileInfo decryptedFile = aes.Decrypt(targetEncryptedFile, targetDecryptedFile);
                Assert.IsNotNull(decryptedFile);
                Assert.IsTrue(File.Exists(targetDecryptedFile));
                Assert.AreEqual
                    (content, await File.ReadAllTextAsync(targetDecryptedFile));
            }
        }

        [TestMethod]
        public async Task DecryptionWithShortKeyAsync()
        {
            using (AES aes = new AES(shortKey))
            {
                if (File.Exists(sourceFile))
                    File.Delete(sourceFile);
                File.WriteAllText(sourceFile, content);

                FileInfo encryptedFile = aes.Encrypt(sourceFile, targetEncryptedFile);
                Assert.IsNotNull(encryptedFile);
                Assert.IsTrue(File.Exists(targetEncryptedFile));

                FileInfo decryptedFile = aes.Decrypt(targetEncryptedFile, targetDecryptedFile);
                Assert.IsNotNull(decryptedFile);
                Assert.IsTrue(File.Exists(targetDecryptedFile));
                Assert.AreEqual
                    (content, await File.ReadAllTextAsync(targetDecryptedFile));
            }
        }

        [TestCleanup]
        public void CleanUp()
        {

            foreach (string filename in new string[]
                { sourceFile,
                    targetDecryptedFile,
                    targetEncryptedFile
                })
            {
                if (File.Exists(filename))
                    File.Delete(filename);
            }
        }
    }
}
