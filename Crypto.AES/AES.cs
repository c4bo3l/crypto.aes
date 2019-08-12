using System;
using System.Text;
using System.IO;
using System.Threading.Tasks;
using System.Linq;

namespace Crypto.AES
{
    public class AES: IDisposable, ICrypto
    {
        #region Properties
        private byte[] _Key;
        private byte[] _Keys;
        private int _Nr;
        #endregion

        public AES(string securityKey)
        {
            if (string.IsNullOrEmpty(securityKey))
                throw new ArgumentNullException("No security key defined");

            ExpandingKey.Process(securityKey, out _Nr, out _Key, out _Keys);
        }

        #region Encrypt
        public byte[] Encrypt(byte[] input)
        {
            if (input == null || input.Length <= 0)
                throw new ArgumentNullException("No input");
            try {
                using (Encryption encryption = new Encryption(_Key, _Keys, _Nr, input)) {
                    byte[] encrypted = encryption.Process();
                    return encrypted == null || encrypted.Length <= 0 ? null : 
                        encrypted.Where(e => e > 0).ToArray();
                }
            }
            catch (Exception) { throw; }
        }

        public string Encrypt(string input) {
            if (string.IsNullOrEmpty(input))
                throw new ArgumentNullException("No input");
            return Convert.ToBase64String(Encrypt(Encoding.ASCII.GetBytes(input)));
        }

        public async Task<FileInfo> Encrypt(string sourceFilePath, string targetFilePath) {
            if (string.IsNullOrEmpty(sourceFilePath))
                throw new ArgumentNullException("Source path is invalid");

            if(string.IsNullOrEmpty(targetFilePath))
                throw new ArgumentNullException("Target path is invalid");

            if (!File.Exists(sourceFilePath))
                throw new FileNotFoundException();
            
            byte[] Input = File.ReadAllBytes(sourceFilePath);
            if (Input == null || Input.Length <= 0)
                throw new FileLoadException();

            FileInfo Output = new FileInfo(targetFilePath);
            try
            {
                using (FileStream Stream = Output.OpenWrite())
                {
                    byte[] encryptedInput = Encrypt(Input);
                    await Stream.WriteAsync(encryptedInput, 0, encryptedInput.Length);
                }
            }
            catch (Exception)
            {
                if (Output.Exists)
                    Output.Delete();
                Output = null;
                throw;
            }

            return Output;
        }
        #endregion

        #region Decrypt
        public byte[] Decrypt(byte[] input)
        {
            if (input == null || input.Length <= 0)
                throw new ArgumentNullException("No input");
            try
            {
                using (Decryption decryption = new Decryption(_Key, _Keys, _Nr, input))
                {
                    byte[] decrypted = decryption.Process();
                    return decrypted == null || decrypted.Length <= 0 ? null : 
                        decrypted.Where(d => d > 0).ToArray();
                }
            }
            catch (Exception) { throw; }
        }

        private string RemoveNullString(string str) {
            return str.Replace("\0", "");
        }

        public string Decrypt(string input)
        {
            if (string.IsNullOrEmpty(input))
                throw new ArgumentNullException("No input");
            return RemoveNullString(Encoding.ASCII
                .GetString(Decrypt(Convert.FromBase64String(input))));
        }

        public async Task<FileInfo> Decrypt(string sourceFilePath, string targetFilePath)
        {
            if (string.IsNullOrEmpty(sourceFilePath))
                throw new ArgumentNullException("Source path is invalid");

            if (string.IsNullOrEmpty(targetFilePath))
                throw new ArgumentNullException("Target path is invalid");

            if (!File.Exists(sourceFilePath))
                throw new FileNotFoundException();
            
            byte[] Input = File.ReadAllBytes(sourceFilePath);
            if (Input == null || Input.Length <= 0)
                throw new FileLoadException();

            FileInfo Output = new FileInfo(targetFilePath);
            try
            {
                using (FileStream Stream = Output.OpenWrite())
                {
                    byte[] decryptedInput = Decrypt(Input);
                    await Stream.WriteAsync(decryptedInput, 0, decryptedInput.Length);
                    Stream.SetLength(decryptedInput.Length);
                }
            }
            catch (Exception)
            {
                if (Output.Exists)
                    Output.Delete();
                Output = null;
                throw;
            }
            return Output;
        }
        #endregion

        public void Dispose()
        {
            _Key = _Keys = null;
            GC.Collect();
        }
    }
}
