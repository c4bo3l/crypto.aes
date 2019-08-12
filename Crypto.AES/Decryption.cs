using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace Crypto.AES
{
    internal class Decryption:IDisposable
    {
        private byte[] _Key;
        private byte[] _Keys;
        private int _Nr;
        private byte[] _Input;

        public Decryption(byte[] key, byte[] keys, int nr, byte[] input)
        {
            if (key == null)
                throw new ArgumentNullException("Key is null");
            if (keys == null)
                throw new ArgumentNullException("Keys is null");
            if (input == null)
                throw new ArgumentNullException("No Input");
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
            byte[] BlockOut = new byte[Common.maxKeyLength];
            byte[] Output = new byte[_Input.Length + 
                ((_Input.Length % Common.maxKeyLength) == 0 ? 0 : 
                (Common.maxKeyLength - (_Input.Length % Common.maxKeyLength)))];
            int Temp = _Input.Length / Common.maxKeyLength;
            for (int i = 0; i < Temp; i++)
            {
                Array.Copy(_Input, i * Common.maxKeyLength, BlockIn, 0, Common.maxKeyLength);
                BlockOut = DecryptingLoop(BlockIn);
                Array.Copy(BlockOut, 0, Output, i * Common.maxKeyLength, Common.maxKeyLength);
            }
            int lastByte = _Input.Length % Common.maxKeyLength;
            if (lastByte > 0)
            {
                BlockIn = new byte[Common.maxKeyLength];
                Array.Copy(_Input, _Input.Length - lastByte, BlockIn, 0, lastByte);
                BlockOut = DecryptingLoop(BlockIn);
                Array.Copy(BlockOut, 0, Output, 
                    Output.Length - Common.maxKeyLength, Common.maxKeyLength);
            }
            return Output;
        }

        private byte[] DecryptingLoop(byte[] block)
        {
            Common.AddRoundKey(block,_Keys, _Nr);
            for (int i = _Nr - 1; i > 0; i--)
            {
                InverseShiftRows(block);
                InverseSubBytes(block);
                Common.AddRoundKey(block,_Keys, i);
                InverseMixColumns(block);
            }
            InverseShiftRows(block);
            InverseSubBytes(block);
            Common.AddRoundKey(block,_Keys, 0);
            return block;
        }

        private void InverseSubBytes(byte[] block)
        {
            for (int i = 0; i < Common.maxKeyLength; i++)
                block[i] = Common.ISBox[block[i]];
        }

        private void InverseShiftRows(byte[] block)
        {
            byte[] temp = new byte[4];
            for (int i = 1; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                    temp[(i + j) % 4] = block[(i * 4) + j];
                for (int j = 0; j < 4; j++)
                    block[(i * 4) + j] = temp[j];
            }
        }

        private void InverseMixColumns(byte[] block)
        {
            byte[,] t = new byte[4, 4];
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    t[i, j] = block[i * 4 + j];
                }
            }
            for (int i = 0; i < 4; i++)
            {
                block[00 + i] = (byte)(Math.PeasantMultiplication.Calculate(14, t[0, i]) ^ 
                    Math.PeasantMultiplication.Calculate(11, t[1, i]) ^ 
                    Math.PeasantMultiplication.Calculate(13, t[2, i]) ^ 
                    Math.PeasantMultiplication.Calculate(9, t[3, i]));
                block[04 + i] = (byte)(Math.PeasantMultiplication.Calculate(9, t[0, i]) ^ 
                    Math.PeasantMultiplication.Calculate(14, t[1, i]) ^ 
                    Math.PeasantMultiplication.Calculate(11, t[2, i]) ^ 
                    Math.PeasantMultiplication.Calculate(13, t[3, i]));
                block[08 + i] = (byte)(Math.PeasantMultiplication.Calculate(13, t[0, i]) ^ 
                    Math.PeasantMultiplication.Calculate(9, t[1, i]) ^ 
                    Math.PeasantMultiplication.Calculate(14, t[2, i]) ^ 
                    Math.PeasantMultiplication.Calculate(11, t[3, i]));
                block[12 + i] = (byte)(Math.PeasantMultiplication.Calculate(11, t[0, i]) ^ 
                    Math.PeasantMultiplication.Calculate(13, t[1, i]) ^ 
                    Math.PeasantMultiplication.Calculate(9, t[2, i]) ^ 
                    Math.PeasantMultiplication.Calculate(14, t[3, i]));
            }
        }

        public void Dispose()
        {
            _Input = _Keys = _Key = null;
            GC.Collect();
        }
    }
}
