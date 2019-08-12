﻿namespace Crypto.AES
{
    public interface ICrypto
    {
        byte[] Encrypt(byte[] input);
        string Encrypt(string input);
        byte[] Decrypt(byte[] input);
        string Decrypt(string input);
    }
}
