using System;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Kalix.ApiCrypto.EC;

/// <summary>
/// Helper class to parse ECDSA based X509Certificates using the newer Cng libraries
/// </summary>
public static class ECDSACertificateParser
{
    /// <summary>
    /// Parses the certificate to get access to the underlying ECDsa implementation
    /// Requires the private key so that the resulting ECDsa can sign
    /// </summary>
    /// <param name="certificate">A certificate from a file or store</param>
    /// <returns>ECDsa that can sign AND verify data</returns>
    public static ECDsa ParsePrivateCertificate(X509Certificate2 certificate)
    {
        // Get the ECDSA private key (needs CngKey lib)
        var privateKey = certificate.GetECDsaPrivateKey();
        if (privateKey == null)
        {
            throw new InvalidOperationException("Certificate does not contain a private key, or is not in the right format");
        }

        return privateKey;
    }

    /// <summary>
    /// Parses the certificate to get access to the underlying ECDsa implementation
    /// Only requires the public key
    /// </summary>
    /// <param name="certificate">A certificate from a file or store</param>
    /// <returns>ECDsa that can verify data only</returns>
    public static ECDsa ParsePublicCertificate(X509Certificate2 certificate)
    {
        return certificate.GetECDsaPublicKey();
    }
}