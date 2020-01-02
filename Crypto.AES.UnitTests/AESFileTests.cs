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
        public async Task FileEncryption()
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
        public async Task StaticEncryptionFile()
        {
            if (File.Exists(sourceFile))
                File.Delete(sourceFile);
            File.WriteAllText(sourceFile, content);

            FileInfo encryptedFile = AES.EncryptFile(key, sourceFile, targetEncryptedFile);
            Assert.IsNotNull(encryptedFile);
            Assert.IsTrue(File.Exists(targetEncryptedFile));
            Assert.AreNotEqual
                (await File.ReadAllTextAsync(targetEncryptedFile), content);
        }

        [TestMethod]
        public async Task EncryptionFileWithShortKey()
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
        public async Task StaticEncryptionFileWithShortKey()
        {
            if (File.Exists(sourceFile))
                File.Delete(sourceFile);
            File.WriteAllText(sourceFile, content);

            FileInfo encryptedFile = AES.EncryptFile(shortKey, sourceFile, targetEncryptedFile);
            Assert.IsNotNull(encryptedFile);
            Assert.IsTrue(File.Exists(targetEncryptedFile));
            Assert.AreNotEqual
                (await File.ReadAllTextAsync(targetEncryptedFile), content);
        }

        [TestMethod]
        public async Task DecryptionFile()
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
        public async Task StaticDecryptionFile()
        {
            if (File.Exists(sourceFile))
                File.Delete(sourceFile);
            File.WriteAllText(sourceFile, content);

            FileInfo encryptedFile = AES.EncryptFile(key, sourceFile, targetEncryptedFile);
            Assert.IsNotNull(encryptedFile);
            Assert.IsTrue(File.Exists(targetEncryptedFile));

            FileInfo decryptedFile = AES.DecryptFile(key, targetEncryptedFile, targetDecryptedFile);
            Assert.IsNotNull(decryptedFile);
            Assert.IsTrue(File.Exists(targetDecryptedFile));
            Assert.AreEqual
                (content, await File.ReadAllTextAsync(targetDecryptedFile));
        }

        [TestMethod]
        public async Task DecryptionFileWithShortKey()
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

        [TestMethod]
        public async Task StaticDecryptionFileWithShortKey()
        {
            if (File.Exists(sourceFile))
                File.Delete(sourceFile);
            File.WriteAllText(sourceFile, content);

            FileInfo encryptedFile = AES.EncryptFile(shortKey, sourceFile, targetEncryptedFile);
            Assert.IsNotNull(encryptedFile);
            Assert.IsTrue(File.Exists(targetEncryptedFile));

            FileInfo decryptedFile = AES.DecryptFile(shortKey, targetEncryptedFile, targetDecryptedFile);
            Assert.IsNotNull(decryptedFile);
            Assert.IsTrue(File.Exists(targetDecryptedFile));
            Assert.AreEqual
                (content, await File.ReadAllTextAsync(targetDecryptedFile));
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
