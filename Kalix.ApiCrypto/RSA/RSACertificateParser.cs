using Security.Cryptography;
using Security.Cryptography.X509Certificates;
using System;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace Kalix.ApiCrypto.RSA
{
    public static class RSACertificateParser
    {
        /// <summary>
        /// Parses the certificate to get access to the underlying RSACng implementation
        /// Requires the private key so that the resulting RSACng can encrypt/sign
        /// </summary>
        /// <param name="certificate">A certificate from a file or store</param>
        /// <returns>RSACngServiceProvider that can verify AND sign/encryt AND decrypt data</returns>
        public static RSACngServiceProvider ParsePrivateCertificate(X509Certificate2 certificate)
        {
            // Get the ECDSA private key (needs CngKey lib)
            var privateKey = certificate.GetCngPrivateKey();
            if (privateKey == null)
            {
                throw new InvalidOperationException("Certificate does not contain a private key, or is not in the right format");
            }

            var rsaCng = new RSACng(privateKey);
            return new RSACngServiceProvider(rsaCng);
        }

        /// <summary>
        /// Parses the certificate to get access to the underlying RSACryptoServiceProvider implementation
        /// Only requires the public key
        /// </summary>
        /// <param name="certificate">A certificate from a file or store</param>
        /// <returns>RSACryptoServiceProvider that can verify/encrypt data only</returns>
        public static RSACryptoServiceProvider ParsePublicCertificate(X509Certificate2 certificate)
        {
            return certificate.PublicKey.Key as RSACryptoServiceProvider;
        }
    }
}
