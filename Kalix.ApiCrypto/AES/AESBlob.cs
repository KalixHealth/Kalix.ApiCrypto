using Kalix.ApiCrypto.RSA;
using System;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Rsa = System.Security.Cryptography.RSA;

namespace Kalix.ApiCrypto.AES
{
    /// <summary>
    /// Helper library to create/use AES blobs encrypted with a RSA certificate
    /// </summary>
    public static class AESBlob
    {
        /// <summary>
        /// Create an AES key that is encrypted using a RSA certificate
        /// </summary>
        /// <param name="keySize">Required AES key size</param>
        /// <param name="rsaPublicCert">RSA public certificate used to sign</param>
        /// <returns>data that can be stored</returns>
        public static byte[] CreateBlob(AESKeySize keySize, X509Certificate2 rsaPublicCert)
        {
            var cert = RSACertificateParser.ParsePublicCertificate(rsaPublicCert);
            return CreateBlob(keySize, cert);
        }

        /// <summary>
        /// Create an AES key that is encrypted using a RSA certificate, this is the parsed version for increased efficiancy
        /// 
        /// To create the parsed cert <see cref="Kalix.ApiCrypto.RSA.RSACertificateParser.ParsePublicCertificate"/>
        /// </summary>
        /// <param name="keySize">Required AES key size</param>
        /// <param name="rsaCert">RSA parsed public certificate used to sign</param>
        /// <param name="rsaPadding">Padding to use during RSA encryption, default is <see cref="RSAEncryptionPadding.OaepSHA256"/></param>
        /// <returns>data that can be stored</returns>
        public static byte[] CreateBlob(AESKeySize keySize, Rsa rsaCert, RSAEncryptionPadding rsaPadding = null)
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

            // Encrypt using the RSA cert and return
            return rsaCert.Encrypt(aesProvider.Key, rsaPadding ?? RSAEncryptionPadding.OaepSHA256);
        }

        /// <summary>
        /// Create an AES encryptor from an encrypted AES key, you can use the encryptor to create 
        /// </summary>
        /// <param name="blob">AES data created from the <see cref="CreateBlob(AESKeySize, X509Certificate2)"/> or <see cref="CreateBlob(AESKeySize, RSAServiceProvider)"/> method</param>
        /// <param name="rsaPrivateCert">RSA certificate to decrypt data, must have a private key</param>
        /// <returns>Encryptor that can be used to encrypt/decrypt any number of documents</returns>
        public static AESEncryptor CreateEncryptor(byte[] blob, X509Certificate2 rsaPrivateCert)
        {
            var cert = RSACertificateParser.ParsePrivateCertificate(rsaPrivateCert);
            return CreateEncryptor(blob, cert);
        }

        /// <summary>
        /// Create an AES encryptor from an encrypted AES key, you can use the encryptor to create. This is the parsed version for increased efficiancy
        /// 
        /// To create the parsed cert <see cref="Kalix.ApiCrypto.RSA.RSACertificateParser.ParsePrivateCertificate"/>
        /// </summary>
        /// <param name="blob">AES data created from the <see cref="CreateBlob(AESKeySize, X509Certificate2)"/> or <see cref="CreateBlob(AESKeySize, Rsa)"/> method</param>
        /// <param name="rsaCert">Parsed RSA certificate to decrypt data, must have a private key</param>
        /// <returns>Encryptor that can be used to encrypt/decrypt any number of documents</returns>
        public static AESEncryptor CreateEncryptor(byte[] blob, Rsa rsaCert, RSAEncryptionPadding rsaPadding = null)
        {
            var key = rsaCert.Decrypt(blob, rsaPadding ?? RSAEncryptionPadding.OaepSHA256);
            return new AESEncryptor(key);
        }
    }
}
