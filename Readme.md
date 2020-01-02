[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

# Introduction

Crypto.AES is a .Net library that implement AES-256 encryption. Because it's been created as .Net Standard 2.0 library, it should be able to use on both .Net Framework and .Net Core projects. For more information please read about [.Net Standard compatibility](https://docs.microsoft.com/en-us/dotnet/standard/net-standard).

The algorithm needs 16 characters as the key. If the key is greater than 16 characters, then it will use first 16 characters. For example, if the key is "ThisIsVeryLongAESKeyYouWon'tNeedIt", then only string "ThisIsVeryLongAE" that would be used. On the other hand, if the key is less than 16 characters, then it would be appended with its substring. For example, if the key is "HelloAES1", then the processed key would be "HelloAES1HelloAE".

What can be processed?
 - String
 - File
 - Array of bytes

# How to use
#### Install with Nuget
    Install-Package Crypto.AES -Version 1.0.3
#### Import the namespace
	using Crypto.AES;
#### String encryption
    using(AES aes = new AES("SHortKEy"))
    { 
	    string toBeEncrypted = "Hello"; 
	    string encrypted = aes.Encrypt(toBeEncrypted);
	    Console.WriteLine(encrypted);
    }

    // OR

    string toBeEncrypted = "Hello"; 
	string encrypted = AES.EncryptString("SHortKEy", toBeEncrypted);
	Console.WriteLine(encrypted);

    // Output: yGYBZQStb1OJnQn0f5Bvwg==
#### String decryption
	using(AES aes = new AES("SHortKEy"))
    { 
	    string toBeDecrypted = "yGYBZQStb1OJnQn0f5Bvwg=="; 
	    string decrypted = aes.Decrypt(toBeDecrypted);
	    Console.WriteLine(decrypted);
    }

    // OR

    string toBeDecrypted = "yGYBZQStb1OJnQn0f5Bvwg=="; 
	string decrypted = AES.DecryptString("SHortKEy", toBeDecrypted);
	Console.WriteLine(decrypted);

    // Output: Hello
#### File encryption
It can be used to encrypt any file. Below is an example to encrypt a text file.

	using(AES aes = new AES("SHortKEy"))
    { 
	    FileInfo encryptedFile = aes.Encrypt("./ToBeEncryptedFile.txt", "./encryptedFile");
    }

    // OR

    FileInfo encryptedFile = AES.EncryptFile("SHortKEy", "./ToBeEncryptedFile.txt", "./encryptedFile");

    // The "encryptedFile" file won't be able to be read as text file.
#### File decryption
	using(AES aes = new AES("SHortKEy"))
    { 
	    FileInfo decryptedFile = aes.Decrypt("./encryptedFile", "./decryptedFile.txt");
    }

    // OR

	FileInfo decryptedFile = AES.DecryptFile("SHortKEy", "./encryptedFile", "./decryptedFile.txt");

    // The "decryptedFile.txt" file will contain decrypted text.

## Contact

If you have any questions or want to report a bug or just want to have a chat and grab a beer :), please feel free to contact me at andrianto.dl@gmail.com.

## License

MIT
