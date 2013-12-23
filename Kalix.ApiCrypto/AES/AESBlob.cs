using Kalix.ApiCrypto.RSA;
using System;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Kalix.ApiCrypto.AES
{
    public static class AESBlob
    {
        public static byte[] CreateBlob(AESKeySize keySize, X509Certificate2 rsaPrivateCert)
        {
            var cert = RSACertificateParser.ParsePrivateCertificate(rsaPrivateCert);
            return CreateBlob(keySize, cert);
        }

        public static byte[] CreateBlob(AESKeySize keySize, RSACngServiceProvider rsaCert)
        {
            int intKeySize;
            switch (keySize)
            {
                case AESKeySize.AES128:
                    intKeySize = 128;
                    break;
                case AESKeySize.AES192:
                    intKeySize = 192;
                    break;
                case AESKeySize.AES256:
                    intKeySize = 256;
                    break;
                default:
                    throw new ArgumentOutOfRangeException("keySize", "Unknown key size");
            }

            var aesProvider = new RijndaelManaged();
            aesProvider.KeySize = intKeySize;
            aesProvider.GenerateKey();

            // This is the key that will be used
            var key = aesProvider.Key;

            // We will now encryt the key using the RSA provider
            var encrypted = rsaCert.EncryptValue(key);

            // Attach the key size to the start
            var keySizeBytes = BitConverter.GetBytes(intKeySize);
            var allData = new byte[encrypted.Length + 4];
            Buffer.BlockCopy(keySizeBytes, 0, allData, 0, 4);
            Buffer.BlockCopy(encrypted, 0, allData, 4, encrypted.Length);

            return allData;
        }
    }
}
