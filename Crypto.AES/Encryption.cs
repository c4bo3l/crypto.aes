using System;

namespace Crypto.AES
{
    internal class Encryption:IDisposable
    {
        private byte[] _Key;
        private byte[] _Keys;
        private int _Nr;
        private byte[] _Input;

        public Encryption(byte[] key, byte[] keys, int nr, byte[] input) {
            if (key == null)
            {
                throw new ArgumentException("Key is null", nameof(key));
            }

            if (keys == null)
            {
                throw new ArgumentException("Keys is null", nameof(keys));
            }

            if (input == null)
            {
                throw new ArgumentException("No Input", nameof(input));
            }

            _Key = new byte[key.Length];
            key.CopyTo(_Key, 0);

            _Keys = new byte[keys.Length];
            keys.CopyTo(_Keys, 0);

            _Input = new byte[input.Length];
            input.CopyTo(_Input, 0);
            _Nr = nr;
        }

        public byte[] Process()
        {
            byte[] BlockIn = new byte[Common.maxKeyLength];
            byte[] BlockOut;
            byte[] Output = new byte[_Input.Length + 
                ((_Input.Length % Common.maxKeyLength) == 0 ? 0 : 
                (Common.maxKeyLength - (_Input.Length % Common.maxKeyLength)))];
            int tmp = _Input.Length / Common.maxKeyLength;
            for (int i = 0; i < tmp; i++)
            {
                Array.Copy(_Input, i * Common.maxKeyLength, BlockIn, 0, Common.maxKeyLength);
                BlockOut = EncryptingLoop(BlockIn);
                Array.Copy(BlockOut, 0, Output, i * Common.maxKeyLength, Common.maxKeyLength);
            }
            int lastByte = _Input.Length % Common.maxKeyLength;
            if (lastByte > 0)
            {
                BlockIn = new byte[Common.maxKeyLength];
                Array.Copy(_Input, _Input.Length - lastByte, BlockIn, 0, lastByte);
                BlockOut = EncryptingLoop(BlockIn);
                Array.Copy(BlockOut, 0, Output, 
                    Output.Length - Common.maxKeyLength, Common.maxKeyLength);
            }
            return Output;
        }

        private byte[] EncryptingLoop(byte[] block)
        {
            Common.AddRoundKey(block, _Keys, 0);
            for (int i = 1; i < _Nr; i++)
            {
                SubBytes(block);
                ShiftRows(block);
                MixColumns(block);
                Common.AddRoundKey(block, _Keys, i);
            }
            SubBytes(block);
            ShiftRows(block);
            Common.AddRoundKey(block, _Keys, _Nr);
            return block;
        }

        private void SubBytes(byte[] block)
        {
            for (int i = 0; i < Common.maxKeyLength; i++)
                block[i] = Common.SBox[block[i]];
        }

        private void ShiftRows(byte[] block)
        {
            byte[] temp = new byte[4];
            for (int i = 1; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                    temp[j] = block[(i * 4) + ((i + j) % 4)];
                
                for (int j = 0; j < 4; j++)
                    block[(i * 4) + j] = temp[j];
            }
        }

        private void MixColumns(byte[] block)
        {
            byte[,] t = new byte[4, 4];
            for (int i = 0; i < 4; i++)
                for (int j = 0; j < 4; j++)
                    t[i, j] = block[i * 4 + j];

            for (int i = 0; i < 4; i++)
            {
                block[00 + i] = (byte)(Math.PeasantMultiplication.Calculate(2, t[0, i]) ^ 
                    Math.PeasantMultiplication.Calculate(3, t[1, i]) ^ t[2, i] ^ t[3, i]);
                block[04 + i] = (byte)(t[0, i] ^ Math.PeasantMultiplication.Calculate(2, t[1, i]) ^ 
                    Math.PeasantMultiplication.Calculate(3, t[2, i]) ^ t[3, i]);
                block[08 + i] = (byte)(t[0, i] ^ t[1, i] ^ Math.PeasantMultiplication.Calculate(2, t[2, i]) ^ 
                    Math.PeasantMultiplication.Calculate(3, t[3, i]));
                block[12 + i] = (byte)(Math.PeasantMultiplication.Calculate(3, t[0, i]) ^ t[1, i] ^ t[2, i] ^ 
                    Math.PeasantMultiplication.Calculate(2, t[3, i]));
            }
        }

        public void Dispose()
        {
            _Input = _Keys = _Key = null;
            GC.Collect();
        }
    }
}
