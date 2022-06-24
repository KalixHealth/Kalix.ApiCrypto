using System;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Kalix.ApiCrypto.EC;

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
            HashingMethod = HashingMethods.Sha256
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
            throw new ArgumentNullException(nameof(buildOptions));
        }

        var name = new X500DistinguishedName(buildOptions.FullSubjectName);
        var curve = (buildOptions.ECCurve ?? ECNamedCurves.P521) switch
        {
            ECNamedCurves.P521 => ECCurve.NamedCurves.nistP521,
            ECNamedCurves.P384 => ECCurve.NamedCurves.nistP384,
            ECNamedCurves.P256 => ECCurve.NamedCurves.nistP256,
            _ => throw new InvalidOperationException("Selected curve is not supported"),
        };

        var hashAlg = (buildOptions.HashingMethod ?? HashingMethods.Sha256).ToHashingName();
        using var ecdsa = ECDsa.Create(curve);

        var request = new CertificateRequest(name, ecdsa, hashAlg);
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, false));
        request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.CrlSign, false));

        return request.CreateSelfSigned(DateTimeOffset.UtcNow, new DateTimeOffset(2039, 12, 31, 23, 59, 59, TimeSpan.Zero));
    }
}