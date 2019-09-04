using System;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Crypto.AES
{
    public class AES : IDisposable, ICrypto
    {
        #region Properties
        private byte[] _Key;
        private byte[] _Keys;
        private int _Nr;
        #endregion

        public AES(string securityKey)
        {
            if (string.IsNullOrEmpty(securityKey))
            {
                throw new ArgumentException("No security key defined", nameof(securityKey));
            }

            ExpandingKey.Process(securityKey, out _Nr, out _Key, out _Keys);
        }

        #region Encrypt
        public byte[] Encrypt(byte[] byteInput)
        {
            if (byteInput == null || byteInput.Length <= 0)
            {
                throw new ArgumentException("No input", nameof(byteInput));
            }

            try
            {
                using (Encryption encryption = new Encryption(_Key, _Keys, _Nr, byteInput))
                {
                    byte[] encrypted = encryption.Process();
                    return encrypted == null || encrypted.Length <= 0 ? null :
                        encrypted.Where(e => e > 0).ToArray();
                }
            }
            catch (Exception ex)
            {
                throw ex;
            }
        }

        public string Encrypt(string stringInput)
        {
            if (string.IsNullOrEmpty(stringInput))
            {
                throw new ArgumentException("No input", nameof(stringInput));
            }
            return Convert.ToBase64String(Encrypt(Encoding.ASCII.GetBytes(stringInput)));
        }

        public FileInfo Encrypt(string sourceFilePath, string targetFilePath)
        {
            if (string.IsNullOrEmpty(targetFilePath))
            {
                throw new ArgumentException("Target path is invalid", nameof(targetFilePath));
            }

            byte[] Input = GetFileBytes(sourceFilePath);

            FileInfo Output = new FileInfo(targetFilePath);
            try
            {
                using (FileStream Stream = Output.OpenWrite())
                {
                    byte[] encryptedInput = Encrypt(Input);
                    Stream.WriteAsync(encryptedInput, 0, encryptedInput.Length).GetAwaiter().GetResult();
                }
            }
            catch (Exception ex)
            {
                if (Output.Exists)
                    Output.Delete();
                throw ex;
            }

            return Output;
        }
        #endregion

        private byte[] GetFileBytes(string sourceFilePath)
        {
            if (string.IsNullOrEmpty(sourceFilePath))
            {
                throw new ArgumentException("Source path is invalid", nameof(sourceFilePath));
            }

            if (!File.Exists(sourceFilePath))
            {
                throw new FileNotFoundException("Source file was not found.");
            }

            byte[] fileBytes = File.ReadAllBytes(sourceFilePath);
            if (fileBytes == null || fileBytes.Length <= 0)
            {
                throw new FileLoadException("Unable to process empty file.");
            }

            return fileBytes;
        }

        #region Decrypt
        public byte[] Decrypt(byte[] byteInput)
        {
            if (byteInput == null || byteInput.Length <= 0)
            {
                throw new ArgumentException("No input", nameof(byteInput));
            }

            try
            {
                using (Decryption decryption = new Decryption(_Key, _Keys, _Nr, byteInput))
                {
                    byte[] decrypted = decryption.Process();
                    return decrypted == null || decrypted.Length <= 0 ? null :
                        decrypted.Where(d => d > 0).ToArray();
                }
            }
            catch (Exception ex)
            {
                throw ex;
            }
        }

        private string RemoveNullString(string str)
        {
            return str.Replace("\0", "");
        }

        public string Decrypt(string stringInput)
        {
            if (string.IsNullOrEmpty(stringInput))
            {
                throw new ArgumentException("No input", nameof(stringInput));
            }

            return RemoveNullString(Encoding.ASCII
                .GetString(Decrypt(Convert.FromBase64String(stringInput))));
        }

        public FileInfo Decrypt(string sourceFilePath, string targetFilePath)
        {
            if (string.IsNullOrEmpty(targetFilePath))
            {
                throw new ArgumentException("Target path is invalid", nameof(targetFilePath));
            }

            byte[] Input = GetFileBytes(sourceFilePath);

            FileInfo Output = new FileInfo(targetFilePath);
            try
            {
                using (FileStream Stream = Output.OpenWrite())
                {
                    byte[] decryptedInput = Decrypt(Input);
                    Stream.WriteAsync(decryptedInput, 0, decryptedInput.Length).GetAwaiter().GetResult();
                    Stream.SetLength(decryptedInput.Length);
                }
            }
            catch (Exception ex)
            {
                if (Output.Exists)
                    Output.Delete();
                throw ex;
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
