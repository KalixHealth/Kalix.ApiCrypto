using Kalix.ApiCrypto.AES;
using Kalix.ApiCrypto.RSA;
using NUnit.Framework;
using System;
using System.IO;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Reactive.Linq;

namespace Kalix.ApiCrypto.Tests.AES
{
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
            encryptor.Encrypt(Observable.Return(data)).Wait();
        }

        [Test]
        public void AES128CreatesWorkableKey()
        {
            var cert = RSACertificateBuilder.CreateNewCertificate(new RSACertificateBuilderOptions { FullSubjectName = "CN=Test", KeySize = 1024 });
            var blob = AESBlob.CreateBlob(AESKeySize.AES128, cert);
            var encryptor = AESBlob.CreateEncryptor(blob, cert);

            var data = Encoding.UTF8.GetBytes("Super secret secret");
            encryptor.Encrypt(Observable.Return(data)).Wait();
        }

        [Test]
        public void AES192CreatesWorkableKey()
        {
            var cert = RSACertificateBuilder.CreateNewCertificate(new RSACertificateBuilderOptions { FullSubjectName = "CN=Test", KeySize = 1024 });
            var blob = AESBlob.CreateBlob(AESKeySize.AES192, cert);
            var encryptor = AESBlob.CreateEncryptor(blob, cert);

            var data = Encoding.UTF8.GetBytes("Super secret secret");
            encryptor.Encrypt(Observable.Return(data)).Wait();
        }

        [Test]
        public void CanCreateWithPublicKeyOnly()
        {
            var cert = RSACertificateBuilder.CreateNewCertificate(new RSACertificateBuilderOptions { FullSubjectName = "CN=Test", KeySize = 1024 });
            var publicCert = new X509Certificate2(cert.Export(X509ContentType.Cert));

            var blob = AESBlob.CreateBlob(AESKeySize.AES256, publicCert);
        }

        [Test]
        [ExpectedException(typeof(InvalidOperationException))]
        public void CannotDecrpytWithoutPrivateKey()
        {
            var cert = RSACertificateBuilder.CreateNewCertificate(new RSACertificateBuilderOptions { FullSubjectName = "CN=Test", KeySize = 1024 });
            var publicCert = new X509Certificate2(cert.Export(X509ContentType.Cert));

            var blob = AESBlob.CreateBlob(AESKeySize.AES256, publicCert);
            AESBlob.CreateEncryptor(blob, publicCert);
        }
    }
}
