using System;
using System.IO;
using System.Linq;
using System.Text;

namespace Crypto.AES
{
    public class AES : ICrypto
    {
        #region Properties
        private byte[] _Key;
        private byte[] _Keys;
        private readonly int _Nr;
        #endregion

        /// <summary>
        /// AES class contructor.
        /// </summary>
        /// <param name="securityKey">
        /// The key will be used in encrypting and decrypting the input.
        /// </param>
        public AES(string securityKey)
        {
            if (string.IsNullOrEmpty(securityKey))
            {
                throw new ArgumentException("No security key defined", nameof(securityKey));
            }

            ExpandingKey.Process(securityKey, out _Nr, out _Key, out _Keys);
        }

        #region Encrypt
        /// <summary>
        /// This function will encrypt array of bytes.
        /// </summary>
        /// <param name="byteInput"></param>
        /// <returns>
        /// Encrypted array of bytes.
        /// </returns>
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

        /// <summary>
        /// Static function to execute array of bytes encryption.
        /// </summary>
        /// <param name="encryptKey">Key string that used to encrypt the array of bytes.</param>
        /// <param name="byteInput"></param>
        /// <returns>
        /// Encrypted array of bytes.
        /// </returns>
        public static byte[] EncryptBytes(string encryptKey, byte[] byteInput)
        {
            using (AES aes = new AES(encryptKey))
            {
                return aes.Encrypt(byteInput);
            }
        }

        /// <summary>
        /// Encrypt a string.
        /// </summary>
        /// <param name="stringInput"></param>
        /// <returns>
        /// Encrypted string.
        /// </returns>
        public string Encrypt(string stringInput)
        {
            if (string.IsNullOrEmpty(stringInput?.Trim()))
            {
                throw new ArgumentException("No input", nameof(stringInput));
            }
            return Convert.ToBase64String(Encrypt(Encoding.ASCII.GetBytes(stringInput)));
        }

        /// <summary>
        /// Static function to execute string encryption.
        /// </summary>
        /// <param name="encryptKey"></param>
        /// <param name="stringInput"></param>
        /// <returns>
        /// Encrypted string.
        /// </returns>
        public static string EncryptString(string encryptKey, string stringInput)
        {
            using (AES aes = new AES(encryptKey))
            {
                return aes.Encrypt(stringInput);
            }
        }

        /// <summary>
        /// Create an encrypted file from the source file.
        /// </summary>
        /// <param name="sourceFilePath">
        /// File path for the source file.
        /// </param>
        /// <param name="targetFilePath">
        /// File path where the encrypted file would be created.
        /// </param>
        /// <returns>
        /// File information of the encrypted file.
        /// </returns>
        public FileInfo Encrypt(string sourceFilePath, string targetFilePath)
        {
            if (string.IsNullOrEmpty(targetFilePath?.Trim()))
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

        /// <summary>
        /// Static function to encrypting a file at sourceFilePath then save the encrypted one at targetFilePath
        /// </summary>
        /// <param name="encryptKey"></param>
        /// <param name="sourceFilePath"></param>
        /// <param name="targetFilePath"></param>
        /// <returns>
        /// File information of the encrypted file.
        /// </returns>
        public static FileInfo EncryptFile(string encryptKey, string sourceFilePath, string targetFilePath)
        {
            using (AES aes = new AES(encryptKey))
            {
                return aes.Encrypt(sourceFilePath, targetFilePath);
            }
        }
        #endregion

        private byte[] GetFileBytes(string sourceFilePath)
        {
            if (string.IsNullOrEmpty(sourceFilePath?.Trim()))
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
        /// <summary>
        /// Decrypt array of bytes.
        /// </summary>
        /// <param name="byteInput"></param>
        /// <returns>
        /// Decrypted array of bytes.
        /// </returns>
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

        /// <summary>
        /// Static function to execute the decryption of array of byte.
        /// </summary>
        /// <param name="decryptKey"></param>
        /// <param name="byteInput"></param>
        /// <returns>
        /// Decrypted array of bytes.
        /// </returns>
        public static byte[] DecryptBytes(string decryptKey, byte[] byteInput)
        {
            using (AES aes = new AES(decryptKey))
            {
                return aes.Decrypt(byteInput);
            }
        }

        private string RemoveNullString(string str)
        {
            return str.Replace("\0", "");
        }

        /// <summary>
        /// Decrypt a string .
        /// </summary>
        /// <param name="stringInput"></param>
        /// <returns>
        /// Decrypted string.
        /// </returns>
        public string Decrypt(string stringInput)
        {
            if (string.IsNullOrEmpty(stringInput?.Trim()))
            {
                throw new ArgumentException("No input", nameof(stringInput));
            }

            return RemoveNullString(Encoding.ASCII
                .GetString(Decrypt(Convert.FromBase64String(stringInput))));
        }

        /// <summary>
        /// Static function to decrypting a string.
        /// </summary>
        /// <param name="decryptKey"></param>
        /// <param name="stringInput"></param>
        /// <returns>
        /// Decrypted string.
        /// </returns>
        public static string DecryptString(string decryptKey, string stringInput)
        {
            using (AES aes = new AES(decryptKey))
            {
                return aes.Decrypt(stringInput);
            }
        }

        /// <summary>
        /// Decrypt a file at sourceFilePath and the result would be saved as a file at targetFilePath
        /// </summary>
        /// <param name="sourceFilePath"></param>
        /// <param name="targetFilePath"></param>
        /// <returns>
        /// File information of the decrypted file.
        /// </returns>
        public FileInfo Decrypt(string sourceFilePath, string targetFilePath)
        {
            if (string.IsNullOrEmpty(targetFilePath?.Trim()))
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

        /// <summary>
        /// Static function for decrypting a file at sourceFilePath and save the decrypted one at targetFilePath.
        /// </summary>
        /// <param name="decryptKey"></param>
        /// <param name="sourceFilePath"></param>
        /// <param name="targetFilePath"></param>
        /// <returns></returns>
        public static FileInfo DecryptFile(string decryptKey, string sourceFilePath, string targetFilePath)
        {
            using (AES aes = new AES(decryptKey))
            {
                return aes.Decrypt(sourceFilePath, targetFilePath);
            }
        }
        #endregion

        /// <summary>
        /// Disposing AES object.
        /// </summary>
        public void Dispose()
        {
            _Key = _Keys = null;
            GC.Collect();
        }
    }
}
