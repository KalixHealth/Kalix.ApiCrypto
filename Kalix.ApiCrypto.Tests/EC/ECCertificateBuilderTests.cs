using Kalix.ApiCrypto.EC;
using NUnit.Framework;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Kalix.ApiCrypto.Tests.EC
{
    [TestFixture]
    public class ECCertificateBuilderTests
    {
        [Test]
        public void CreateWithDefaultOptions()
        {
            var cert = ECCertificateBuilder.CreateNewSigningCertificate("Test");

            Assert.AreEqual("CN=Test", cert.Subject);
            Assert.AreEqual("sha256ECDSA", cert.SignatureAlgorithm.FriendlyName);
            Assert.IsTrue(cert.HasPrivateKey);
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

            Assert.AreEqual("CN=Test", cert.Subject);
            Assert.AreEqual("sha256ECDSA", cert.SignatureAlgorithm.FriendlyName);
            Assert.IsTrue(cert.HasPrivateKey);
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

            Assert.AreEqual("CN=Test", cert.Subject);
            Assert.AreEqual("sha256ECDSA", cert.SignatureAlgorithm.FriendlyName);
            Assert.IsTrue(cert.HasPrivateKey);
        }

        [Test]
        public void CreateWithSha1Hash()
        {
            var options = new ECCertificateBuilderOptions
            {
                FullSubjectName = "CN=Test",
                HashingMethod = HashingMethods.Sha1
            };

            var cert = ECCertificateBuilder.CreateNewSigningCertificate(options);

            Assert.AreEqual("CN=Test", cert.Subject);
            Assert.AreEqual("sha1ECDSA", cert.SignatureAlgorithm.FriendlyName);
            Assert.IsTrue(cert.HasPrivateKey);
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

            Assert.AreEqual("CN=Test", cert.Subject);
            Assert.AreEqual("sha384ECDSA", cert.SignatureAlgorithm.FriendlyName);
            Assert.IsTrue(cert.HasPrivateKey);
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

            Assert.AreEqual("CN=Test", cert.Subject);
            Assert.AreEqual("sha512ECDSA", cert.SignatureAlgorithm.FriendlyName);
            Assert.IsTrue(cert.HasPrivateKey);
        }

        [Test]
        public void SurvivesExportImport()
        {
            var options = new ECCertificateBuilderOptions
            {
                FullSubjectName = "CN=Test",
                ECKeyName = "KeyTestTemp",
                HashingMethod = HashingMethods.Sha512
            };

            var cert = ECCertificateBuilder.CreateNewSigningCertificate(options);
            var data = cert.Export(X509ContentType.Pkcs12, "password");

            if (CngKey.Exists("KeyTestTemp"))
            {
                var objCngKey = CngKey.Open("KeyTestTemp");
                objCngKey.Delete();
            }

            var reloaded = new X509Certificate2(data, "password");
            ECDSACertificateParser.ParsePrivateCertificate(reloaded);
        }
    }
}
