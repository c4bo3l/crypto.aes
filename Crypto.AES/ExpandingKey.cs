using System.Text;
using System;

namespace Crypto.AES
{
    internal class ExpandingKey
    {
        private static string NormalizeKey(string key) {
            if (string.IsNullOrEmpty(key))
                throw new ArgumentNullException("Key string is empty");
            if (key.Length > Common.maxKeyLength)
                key = key.Substring(0, Common.maxKeyLength);
            else if (key.Length < Common.maxKeyLength)
            {
                int index = 0;
                while (key.Length < Common.maxKeyLength) {
                    key += key[index].ToString();
                    index++;
                }
            }
            return key;
        }

        public static void Process(string key, out int nr, out byte[] bKey, out byte[] bKeys)
        {
            key = NormalizeKey(key);
            int Nk = key.Length / 4;
            nr = Nk + 6;
            bKey = new byte[key.Length * 8];
            bKeys = new byte[4 * 4 * (nr + 1)];
            Encoding.ASCII.GetBytes(key).CopyTo(bKey, 0);
            bKey.CopyTo(bKeys, 0);
            byte[] temp = new byte[4];
            for (int i = Nk; i < 4 * (nr + 1); i++)
            {
                for (int j = 0; j < 4; j++)
                    temp[j] = bKeys[(i - 1) * 4 + j];

                if (i % Nk == 0)
                {
                    temp = SubWord(RotWord(temp));
                    temp[0] = (byte)(temp[0] ^ Common.Round[i / Nk]);
                }
                else if (Nk > 6 && (i % Nk == 4))
                    temp = SubWord(temp);

                for (int j = 0; j < 4; j++)
                    bKeys[i * 4 + j] = (byte)(bKeys[(i - Nk) * 4 + j] ^ temp[j]);
            }
        }

        private static byte[] SubWord(byte[] input)
        {
            return new byte[4]{
                    Common.SBox[input[0]],
                    Common.SBox[input[1]],
                    Common.SBox[input[2]],
                    Common.SBox[input[3]]
                };
        }

        private static byte[] RotWord(byte[] input)
        {
            return new byte[4] {
                input[1],
                input[2],
                input[3],
                input[0]
            };
        }
    }
}
