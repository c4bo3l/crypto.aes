using System;
using System.IO;

namespace Crypto.AES
{
    public interface ICrypto : IDisposable
    {
        byte[] Encrypt(byte[] byteInput);
        byte[] Decrypt(byte[] byteInput);

        string Encrypt(string stringInput);
        string Decrypt(string stringInput);

        FileInfo Encrypt(string sourceFilePath, string targetFilePath);
        FileInfo Decrypt(string sourceFilePath, string targetFilePath);
    }
}
