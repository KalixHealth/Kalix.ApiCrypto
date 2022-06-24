using System;
using System.Security.Cryptography.X509Certificates;
using Rsa = System.Security.Cryptography.RSA;

namespace Kalix.ApiCrypto.RSA;

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
    /// <returns>RSA instance that can verify AND sign/encryt AND decrypt data</returns>
    public static Rsa ParsePrivateCertificate(X509Certificate2 certificate)
    {
        var key = certificate.GetRSAPrivateKey();
        if (key == null)
        {
            throw new InvalidOperationException("No private key found");
        }
        return key;
    }

    /// <summary>
    /// Parses the certificate to get access to the underlying RSAServiceProvider implementation
    /// Only requires the public key
    /// </summary>
    /// <param name="certificate">A certificate from a file or store</param>
    /// <returns>RSA instance that can verify/encrypt data only</returns>
    public static Rsa ParsePublicCertificate(X509Certificate2 certificate)
    {
        return certificate.GetRSAPublicKey();
    }
}