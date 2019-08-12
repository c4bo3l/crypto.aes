using Microsoft.VisualStudio.TestTools.UnitTesting;
using System.IO;
using System;

namespace Crypto.AES.UnitTests
{
    [TestClass]
    public class AESFileTests
    {
        private string key = "ThisKeyMust16Ch";
        private string sourceFile = "./ToBeEncryptedFile.txt";
        private string targetEncryptedFile = "./encryptedFile.txt";
        private string targetDecryptedFile = "./decryptedFile.txt";
        private string content = "This is a text.";

        [TestMethod]
        public async System.Threading.Tasks.Task EncryptionAsync()
        {
            using (AES aes = new AES(key))
            {
                if (File.Exists(sourceFile))
                    File.Delete(sourceFile);
                File.WriteAllText(sourceFile, content);

                FileInfo encryptedFile =
                    await aes.Encrypt(sourceFile, targetEncryptedFile);
                Assert.IsNotNull(encryptedFile);
                Assert.IsTrue(File.Exists(targetEncryptedFile));
                Assert.AreNotEqual<string>
                    (await File.ReadAllTextAsync(targetEncryptedFile), content);
            }
        }

        [TestMethod]
        public async System.Threading.Tasks.Task DecryptionAsync()
        {
            using (AES aes = new AES(key))
            {
                if (File.Exists(sourceFile))
                    File.Delete(sourceFile);
                File.WriteAllText(sourceFile, content);

                FileInfo encryptedFile =
                    await aes.Encrypt(sourceFile, targetEncryptedFile);
                Assert.IsNotNull(encryptedFile);
                Assert.IsTrue(File.Exists(targetEncryptedFile));

                FileInfo decryptedFile = 
                    await aes.Decrypt(targetEncryptedFile, targetDecryptedFile);
                Assert.IsNotNull(decryptedFile);
                Assert.IsTrue(File.Exists(targetDecryptedFile));
                Assert.AreEqual<string>
                    (content, await File.ReadAllTextAsync(targetDecryptedFile));
            }
        }

        [TestCleanup]
        public void CleanUp() {

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
