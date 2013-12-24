using Security.Cryptography;
using Security.Cryptography.X509Certificates;
using System;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Kalix.ApiCrypto.RSA
{
    /// <summary>
    /// Helper class to build X509Certificates using the RSA algorithm
    /// 
    /// Note that it uses the newer Cng library
    /// </summary>
    public static class RSACertificateBuilder
    {
        /// <summary>
        /// Create a ECDSA based certificate with the given subject name. Uses a key size of 4096 by default.
        /// </summary>
        /// <param name="subjectName">Subject Name of the certificate (Omit the CN= part)</param>
        /// <returns>An exportable X509Certificate2 object (with private key)</returns>
        public static X509Certificate2 CreateNewCertificate(string subjectName)
        {
            return CreateNewCertificate(new RSACertificateBuilderOptions
            {
                FullSubjectName = "CN=" + subjectName,
                KeySize = 4096,
                HashingMethod = HashingMethods.Sha256,
                RSAKeyName = "RSA_" + subjectName
            });
        }

        /// <summary>
        /// Create a RSA based certificate (to be used with encryption) with the given options
        /// </summary>
        /// <param name="buildOptions">Allows for more advanced configuration</param>
        /// <returns>An exportable X509Certificate2 object (with private key)</returns>
        public static X509Certificate2 CreateNewCertificate(RSACertificateBuilderOptions buildOptions)
        {
            if (buildOptions == null)
            {
                throw new ArgumentNullException("buildOptions");
            }

            string keyName = buildOptions.RSAKeyName ?? "RSAKey";

            CngKey objCngKey = null;
            if (CngKey.Exists(keyName))
            {
                objCngKey = CngKey.Open(keyName);
                objCngKey.Delete();
            }

            var creationParameters = new CngKeyCreationParameters();
            creationParameters.ExportPolicy = CngExportPolicies.AllowExport;
            creationParameters.KeyUsage = CngKeyUsages.AllUsages;
            creationParameters.Provider = CngProvider.MicrosoftSoftwareKeyStorageProvider;
            var keySizeProperty = new CngProperty("Length", BitConverter.GetBytes(buildOptions.KeySize ?? 4096), CngPropertyOptions.None);
            creationParameters.Parameters.Add(keySizeProperty);

            objCngKey = CngKey.Create(CngAlgorithm2.Rsa, keyName, creationParameters);

            var name = new X500DistinguishedName(buildOptions.FullSubjectName);

            X509CertificateSignatureAlgorithm certAlg;
            switch (buildOptions.HashingMethod ?? HashingMethods.Sha256)
            {
                case HashingMethods.Sha1:
                    certAlg = X509CertificateSignatureAlgorithm.RsaSha1;
                    break;
                case HashingMethods.Sha256:
                    certAlg = X509CertificateSignatureAlgorithm.RsaSha256;
                    break;
                case HashingMethods.Sha384:
                    certAlg = X509CertificateSignatureAlgorithm.RsaSha384;
                    break;
                case HashingMethods.Sha512:
                    certAlg = X509CertificateSignatureAlgorithm.RsaSha512;
                    break;
                default:
                    throw new InvalidOperationException("Selected hashing method is not supported");
            }

            var options = new X509CertificateCreationParameters(name)
            {
                SignatureAlgorithm = certAlg,
                TakeOwnershipOfKey = true
            };

            return objCngKey.CreateSelfSignedCertificate(options);
        }
    }
}
