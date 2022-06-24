using System;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Rsa = System.Security.Cryptography.RSA;

namespace Kalix.ApiCrypto.RSA;

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
            HashingMethod = HashingMethods.Sha256
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
            throw new ArgumentNullException(nameof(buildOptions));
        }

        var name = new X500DistinguishedName(buildOptions.FullSubjectName);
        var hashAlg = (buildOptions.HashingMethod ?? HashingMethods.Sha256).ToHashingName();

        using var rsa = Rsa.Create(buildOptions.KeySize ?? 4096);
        var request = new CertificateRequest(name, rsa, hashAlg, RSASignaturePadding.Pkcs1);
        request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.CrlSign | X509KeyUsageFlags.DataEncipherment | X509KeyUsageFlags.DigitalSignature, false));

        return request.CreateSelfSigned(DateTimeOffset.UtcNow, new DateTimeOffset(2039, 12, 31, 23, 59, 59, TimeSpan.Zero));
    }
}