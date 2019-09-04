using System.IO;
using System.Threading.Tasks;

namespace Crypto.AES
{
    public interface ICrypto
    {
        byte[] Encrypt(byte[] input);
        byte[] Decrypt(byte[] input);

        string Encrypt(string input);
        string Decrypt(string input);

        FileInfo Encrypt(string sourceFilePath, string targetFilePath);
        FileInfo Decrypt(string sourceFilePath, string targetFilePath);
    }
}
