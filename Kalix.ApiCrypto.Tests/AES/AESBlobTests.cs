using Kalix.ApiCrypto.AES;
using Kalix.ApiCrypto.RSA;
using NUnit.Framework;
using System;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace Kalix.ApiCrypto.Tests.AES;

[TestFixture]
public class AESBlobTests
{
    [Test]
    public void AES256CreatesWorkableKey()
    {
        var cert = RSACertificateBuilder.CreateNewCertificate(new RSACertificateBuilderOptions { FullSubjectName = "CN=Test", KeySize = 1024 });
        var blob = AESBlob.CreateBlob(AESKeySize.AES256, cert);
        var encryptor = AESBlob.CreateEncryptor(blob, cert);

        var data = Encoding.UTF8.GetBytes("Super secret secret");
        encryptor.Encrypt(data);
    }

    [Test]
    public void AES128CreatesWorkableKey()
    {
        var cert = RSACertificateBuilder.CreateNewCertificate(new RSACertificateBuilderOptions { FullSubjectName = "CN=Test", KeySize = 1024 });
        var blob = AESBlob.CreateBlob(AESKeySize.AES128, cert);
        var encryptor = AESBlob.CreateEncryptor(blob, cert);

        var data = Encoding.UTF8.GetBytes("Super secret secret");
        encryptor.Encrypt(data);
    }

    [Test]
    public void AES192CreatesWorkableKey()
    {
        var cert = RSACertificateBuilder.CreateNewCertificate(new RSACertificateBuilderOptions { FullSubjectName = "CN=Test", KeySize = 1024 });
        var blob = AESBlob.CreateBlob(AESKeySize.AES192, cert);
        var encryptor = AESBlob.CreateEncryptor(blob, cert);

        var data = Encoding.UTF8.GetBytes("Super secret secret");
        encryptor.Encrypt(data);
    }

    [Test]
    public void CanCreateWithPublicKeyOnly()
    {
        var cert = RSACertificateBuilder.CreateNewCertificate(new RSACertificateBuilderOptions { FullSubjectName = "CN=Test", KeySize = 1024 });
        var publicCert = X509CertificateLoader.LoadCertificate(cert.Export(X509ContentType.Cert));

        AESBlob.CreateBlob(AESKeySize.AES256, publicCert);
    }

    [Test]
    public void CannotDecrpytWithoutPrivateKey()
    {
        Assert.Throws<InvalidOperationException>(() =>
        {
            var cert = RSACertificateBuilder.CreateNewCertificate(new RSACertificateBuilderOptions { FullSubjectName = "CN=Test", KeySize = 1024 });
            var publicCert = X509CertificateLoader.LoadCertificate(cert.Export(X509ContentType.Cert));

            var blob = AESBlob.CreateBlob(AESKeySize.AES256, publicCert);
            AESBlob.CreateEncryptor(blob, publicCert);
        });
    }
}