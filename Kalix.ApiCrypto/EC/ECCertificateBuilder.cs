using Security.Cryptography;
using Security.Cryptography.X509Certificates;
using System;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Kalix.ApiCrypto.EC
{
    /// <summary>
    /// Helper class to build X509Certificates using the EC based algorithms
    /// Right now it only supports signing certificates using ECDSA
    /// 
    /// Note that it uses the newer Cng library
    /// </summary>
    public static class ECCertificateBuilder
    {
        /// <summary>
        /// Create a ECDSA based certificate with the given subject name. Uses the P521 curve and Sha256 by default.
        /// </summary>
        /// <param name="subjectName">Subject Name of the certificate (Omit the CN= part)</param>
        /// <returns>An exportable X509Certificate2 object (with private key)</returns>
        public static X509Certificate2 CreateNewSigningCertificate(string subjectName)
        {
            return CreateNewSigningCertificate(new ECCertificateBuilderOptions
            {
                FullSubjectName = "CN=" + subjectName,
                ECCurve = ECNamedCurves.P521,
                HashingMethod = HashingMethods.Sha256,
                ECKeyName = "ECDSA_" + subjectName
            });
        }

        /// <summary>
        /// Create a ECDSA based certificate with the given options
        /// </summary>
        /// <param name="buildOptions">Allows for more advanced configuration</param>
        /// <returns>An exportable X509Certificate2 object (with private key)</returns>
        public static X509Certificate2 CreateNewSigningCertificate(ECCertificateBuilderOptions buildOptions)
        {
            if(buildOptions == null)
            {
                throw new ArgumentNullException("buildOptions");
            }

            string keyName = buildOptions.ECKeyName ?? "ECDSAKey";

            CngKey objCngKey = null;
            if (CngKey.Exists(keyName))
            {
                objCngKey = CngKey.Open(keyName);
                objCngKey.Delete();
            }

            var creationParameters = new CngKeyCreationParameters();
            creationParameters.ExportPolicy = CngExportPolicies.AllowExport;
            creationParameters.KeyUsage = CngKeyUsages.Signing;

            CngAlgorithm keyAlg;
            switch(buildOptions.ECCurve ?? ECNamedCurves.P521)
            {
                case ECNamedCurves.P521:
                    keyAlg = CngAlgorithm.ECDsaP521;
                    break;
                case ECNamedCurves.P384:
                    keyAlg = CngAlgorithm.ECDsaP384;
                    break;
                case ECNamedCurves.P256:
                    keyAlg = CngAlgorithm.ECDsaP256;
                    break;
                default:
                    throw new InvalidOperationException("Selected curve is not supported");
            }

            objCngKey = CngKey.Create(keyAlg, keyName, creationParameters);

            var name = new X500DistinguishedName(buildOptions.FullSubjectName);

            X509CertificateSignatureAlgorithm certAlg;
            switch(buildOptions.HashingMethod ?? HashingMethods.Sha256)
            {
                case HashingMethods.Sha1:
                    certAlg = X509CertificateSignatureAlgorithm.ECDsaSha1;
                    break;
                case HashingMethods.Sha256:
                    certAlg = X509CertificateSignatureAlgorithm.ECDsaSha256;
                    break;
                case HashingMethods.Sha384:
                    certAlg = X509CertificateSignatureAlgorithm.ECDsaSha384;
                    break;
                case HashingMethods.Sha512:
                    certAlg = X509CertificateSignatureAlgorithm.ECDsaSha512;
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
