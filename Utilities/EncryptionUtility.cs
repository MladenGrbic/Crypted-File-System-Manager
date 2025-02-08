using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;

namespace KriptografijaProjekat.Utilities
{
    public static class EncryptionUtility
    {
        // Enkripcija AESom
        public static void EncryptFileAES(string inputPath, string outputPath, byte[] key, byte[] iv)
        {

            using var aes = Aes.Create();
            aes.Key = key;
            aes.IV = iv[..16];
            aes.Padding = PaddingMode.PKCS7;

            using var fsOutput = new FileStream(outputPath, FileMode.Create);
            using var cryptoStream = new CryptoStream(fsOutput, aes.CreateEncryptor(), CryptoStreamMode.Write);
            using var fsInput = new FileStream(inputPath, FileMode.Open);

            fsInput.CopyTo(cryptoStream);

            cryptoStream.FlushFinalBlock();
        }

        // Dekripcija AESom
        public static void DecryptFileAES(string inputPath, string outputPath, byte[] key, byte[] iv)
        {
            using var aes = Aes.Create();
            aes.Key = key;
            aes.IV = iv[..16];
            aes.Padding = PaddingMode.PKCS7;

            using var fsInput = new FileStream(inputPath, FileMode.Open);
            using var cryptoStream = new CryptoStream(fsInput, aes.CreateDecryptor(), CryptoStreamMode.Read);
            using var fsOutput = new FileStream(outputPath, FileMode.Create);

            cryptoStream.CopyTo(fsOutput);
        }


        // Enkripcija TripleDESom
        public static void EncryptWithTripleDES(string inputPath, string outputPath, byte[] key, byte[] iv)
        {
            using var tripleDES = TripleDES.Create();
            byte[] tDESKey = key[..24];
            byte[] tDESiv= iv[..8];
            tripleDES.Key = tDESKey;
            tripleDES.IV = tDESiv;

            using var fsOutput = new FileStream(outputPath, FileMode.Create);
            using var cryptoStream = new CryptoStream(fsOutput, tripleDES.CreateEncryptor(), CryptoStreamMode.Write);
            using var fsInput = new FileStream(inputPath, FileMode.Open);

            fsInput.CopyTo(cryptoStream);

            cryptoStream.FlushFinalBlock();
        }

        // Dekripcija TripleDESom
        public static void DecryptWithTripleDES(string inputPath, string outputPath, byte[] key, byte[] iv)
        {
            using var tripleDES = TripleDES.Create();
            byte[] tDESKey = key[..24];
            byte[] tDESiv = iv[..8];
            tripleDES.Key = tDESKey;
            tripleDES.IV = tDESiv;

            using var fsInput = new FileStream(inputPath, FileMode.Open);
            using var cryptoStream = new CryptoStream(fsInput, tripleDES.CreateDecryptor(), CryptoStreamMode.Read);
            using var fsOutput = new FileStream(outputPath, FileMode.Create);

            cryptoStream.CopyTo(fsOutput);
        }

        // Enkripcija BlowFish algoritmom
        public static void EncryptWithBlowfish(string inputPath, string outputPath, byte[] key, byte[] iv)
        {
            var engine = new BlowfishEngine();
            var blockCipher = new CfbBlockCipher(engine, 8); // Using CFB mode for Blowfish
            var cipher = new BufferedBlockCipher(blockCipher);
            byte[] blowFIV = iv[..8];

            cipher.Init(true, new ParametersWithIV(new KeyParameter(key), blowFIV));

            ProcessFile(cipher, inputPath, outputPath);
        }

        // Dekripcija BlowFish algoritmom
        public static void DecryptWithBlowfish(string inputPath, string outputPath, byte[] key, byte[] iv)
        {
            var engine = new BlowfishEngine();
            var blockCipher = new CfbBlockCipher(engine, 8); // Using CFB mode for Blowfish
            var cipher = new BufferedBlockCipher(blockCipher);
            byte[] blowFIV = iv[..8];

            cipher.Init(false, new ParametersWithIV(new KeyParameter(key), blowFIV));

            ProcessFile(cipher, inputPath, outputPath);
        }

        //File procesor za Blowfish
        private static void ProcessFile(IBufferedCipher cipher, string inputPath, string outputPath)
        {
            using var fsInput = new FileStream(inputPath, FileMode.Open);
            using var fsOutput = new FileStream(outputPath, FileMode.Create);

            var inputBytes = new byte[fsInput.Length];
            fsInput.Read(inputBytes, 0, inputBytes.Length);

            var outputBytes = cipher.DoFinal(inputBytes);
            fsOutput.Write(outputBytes, 0, outputBytes.Length);
        }
    }
}

