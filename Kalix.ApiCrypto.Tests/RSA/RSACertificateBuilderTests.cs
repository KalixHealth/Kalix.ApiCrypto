﻿using Kalix.ApiCrypto.RSA;
using NUnit.Framework;

namespace Kalix.ApiCrypto.Tests.RSA;

[TestFixture]
public class RSACertificateBuilderTests
{
    [Test]
    public void CreateWithDefaultOptions()
    {
        var cert = RSACertificateBuilder.CreateNewCertificate("Test");

        Assert.That("CN=Test", Is.EqualTo(cert.Subject));
        Assert.That("sha256RSA", Is.EqualTo(cert.SignatureAlgorithm.FriendlyName));
        Assert.That(cert.HasPrivateKey);
    }

    [Test]
    public void CreateWith2048KeySize()
    {
        var options = new RSACertificateBuilderOptions
        {
            FullSubjectName = "CN=Test",
            KeySize = 2048
        };

        var cert = RSACertificateBuilder.CreateNewCertificate(options);

        Assert.That("CN=Test", Is.EqualTo(cert.Subject));
        Assert.That("sha256RSA", Is.EqualTo(cert.SignatureAlgorithm.FriendlyName));
        Assert.That(cert.HasPrivateKey);
    }

    [Test]
    public void CreateWith7168KeySize()
    {
        var options = new RSACertificateBuilderOptions
        {
            FullSubjectName = "CN=Test",
            KeySize = 7168
        };

        var cert = RSACertificateBuilder.CreateNewCertificate(options);

        Assert.That("CN=Test", Is.EqualTo(cert.Subject));
        Assert.That("sha256RSA", Is.EqualTo(cert.SignatureAlgorithm.FriendlyName));
        Assert.That(cert.HasPrivateKey);
    }

    [Test]
    public void CreateWithSha384Hash()
    {
        var options = new RSACertificateBuilderOptions
        {
            FullSubjectName = "CN=Test",
            HashingMethod = HashingMethods.Sha384
        };

        var cert = RSACertificateBuilder.CreateNewCertificate(options);

        Assert.That("CN=Test", Is.EqualTo(cert.Subject));
        Assert.That("sha384RSA", Is.EqualTo(cert.SignatureAlgorithm.FriendlyName));
        Assert.That(cert.HasPrivateKey);
    }

    [Test]
    public void CreateWithSha512Hash()
    {
        var options = new RSACertificateBuilderOptions
        {
            FullSubjectName = "CN=Test",
            HashingMethod = HashingMethods.Sha512
        };

        var cert = RSACertificateBuilder.CreateNewCertificate(options);

        Assert.That("CN=Test", Is.EqualTo(cert.Subject));
        Assert.That("sha512RSA", Is.EqualTo(cert.SignatureAlgorithm.FriendlyName));
        Assert.That(cert.HasPrivateKey);
    }
}