using Kalix.ApiCrypto.EC;
using NUnit.Framework;
using System.Security.Cryptography.X509Certificates;

namespace Kalix.ApiCrypto.Tests.EC;

[TestFixture]
public class ECCertificateBuilderTests
{
    [Test]
    public void CreateWithDefaultOptions()
    {
        var cert = ECCertificateBuilder.CreateNewSigningCertificate("Test");

        Assert.That("CN=Test", Is.EqualTo(cert.Subject));
        Assert.That("sha256ECDSA", Is.EqualTo(cert.SignatureAlgorithm.FriendlyName));
        Assert.That(cert.HasPrivateKey);
    }

    [Test]
    public void CreateWithP384Curve()
    {
        var options = new ECCertificateBuilderOptions
        {
            FullSubjectName = "CN=Test",
            ECCurve = ECNamedCurves.P384
        };

        var cert = ECCertificateBuilder.CreateNewSigningCertificate(options);

        Assert.That("CN=Test", Is.EqualTo(cert.Subject));
        Assert.That("sha256ECDSA", Is.EqualTo(cert.SignatureAlgorithm.FriendlyName));
        Assert.That(cert.HasPrivateKey);
    }

    [Test]
    public void CreateWithP256Curve()
    {
        var options = new ECCertificateBuilderOptions
        {
            FullSubjectName = "CN=Test",
            ECCurve = ECNamedCurves.P256
        };

        var cert = ECCertificateBuilder.CreateNewSigningCertificate(options);

        Assert.That("CN=Test", Is.EqualTo(cert.Subject));
        Assert.That("sha256ECDSA", Is.EqualTo(cert.SignatureAlgorithm.FriendlyName));
        Assert.That(cert.HasPrivateKey);
    }

    [Test]
    public void CreateWithSha384Hash()
    {
        var options = new ECCertificateBuilderOptions
        {
            FullSubjectName = "CN=Test",
            HashingMethod = HashingMethods.Sha384
        };

        var cert = ECCertificateBuilder.CreateNewSigningCertificate(options);

        Assert.That("CN=Test", Is.EqualTo(cert.Subject));
        Assert.That("sha384ECDSA", Is.EqualTo(cert.SignatureAlgorithm.FriendlyName));
        Assert.That(cert.HasPrivateKey);
    }

    [Test]
    public void CreateWithSha512Hash()
    {
        var options = new ECCertificateBuilderOptions
        {
            FullSubjectName = "CN=Test",
            HashingMethod = HashingMethods.Sha512
        };

        var cert = ECCertificateBuilder.CreateNewSigningCertificate(options);

        Assert.That("CN=Test", Is.EqualTo(cert.Subject));
        Assert.That("sha512ECDSA", Is.EqualTo(cert.SignatureAlgorithm.FriendlyName));
        Assert.That(cert.HasPrivateKey);
    }

    [Test]
    public void SurvivesExportImport()
    {
        var options = new ECCertificateBuilderOptions
        {
            FullSubjectName = "CN=Test",
            HashingMethod = HashingMethods.Sha512
        };

        var cert = ECCertificateBuilder.CreateNewSigningCertificate(options);
        var data = cert.Export(X509ContentType.Pkcs12, "password");

        var reloaded = X509CertificateLoader.LoadPkcs12(data, "password");
        ECDSACertificateParser.ParsePrivateCertificate(reloaded);
    }
}