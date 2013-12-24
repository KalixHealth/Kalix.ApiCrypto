using Security.Cryptography;
using Security.Cryptography.X509Certificates;
using System;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Kalix.ApiCrypto.RSA
{
    /// <summary>
    /// Helper class to parse RSA X509Certificates using the newer Cng libraries
    /// </summary>
    public static class RSACertificateParser
    {
        /// <summary>
        /// Parses the certificate to get access to the underlying RSAServiceProvider implementation
        /// Requires the private key so that the resulting RSAServiceProvider can encrypt/sign
        /// </summary>
        /// <param name="certificate">A certificate from a file or store</param>
        /// <returns>RSAServiceProvider that can verify AND sign/encryt AND decrypt data</returns>
        public static RSAServiceProvider ParsePrivateCertificate(X509Certificate2 certificate)
        {
            // Get the ECDSA private key (needs CngKey lib)
            var privateKey = certificate.GetCngPrivateKey();
            if (privateKey == null)
            {
                throw new InvalidOperationException("Certificate does not contain a private key, or is not in the right format");
            }

            var rsaCng = new RSACng(privateKey);
            return new RSAServiceProvider(rsaCng);
        }

        /// <summary>
        /// Parses the certificate to get access to the underlying RSAServiceProvider implementation
        /// Only requires the public key
        /// </summary>
        /// <param name="certificate">A certificate from a file or store</param>
        /// <returns>RSAServiceProvider that can verify/encrypt data only</returns>
        public static RSAServiceProvider ParsePublicCertificate(X509Certificate2 certificate)
        {
            var provider = certificate.PublicKey.Key as RSACryptoServiceProvider;
            var parameters = provider.ExportParameters(false);
            var rsaCng = new RSACng();
            rsaCng.ImportParameters(parameters);

            return new RSAServiceProvider(rsaCng);
        }
    }
}
