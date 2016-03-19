using Kalix.ApiCrypto.EC;
using NUnit.Framework;
using System;
using System.Security.Cryptography.X509Certificates;

namespace Kalix.ApiCrypto.Tests.EC
{
    [TestFixture]
    public class ECCertificateParserTest
    {
        [TestFixture]
        public class ParsePrivateCertificateMethod : ECCertificateParserTest
        {
            [Test]
            public void P521CertificateCorrectlyParses()
            {
                var options = new ECCertificateBuilderOptions
                {
                    FullSubjectName = "CN=Test",
                    ECCurve = ECNamedCurves.P521
                };

                var cert = ECCertificateBuilder.CreateNewSigningCertificate(options);

                var cng = ECDSACertificateParser.ParsePrivateCertificate(cert);

                Assert.IsNotNull(cng);
            }

            [Test]
            public void P384CertificateCorrectlyParses()
            {
                var options = new ECCertificateBuilderOptions
                {
                    FullSubjectName = "CN=Test",
                    ECCurve = ECNamedCurves.P384
                };

                var cert = ECCertificateBuilder.CreateNewSigningCertificate(options);

                var cng = ECDSACertificateParser.ParsePrivateCertificate(cert);

                Assert.IsNotNull(cng);
            }

            [Test]
            public void P256CertificateCorrectlyParses()
            {
                var options = new ECCertificateBuilderOptions
                {
                    FullSubjectName = "CN=Test",
                    ECCurve = ECNamedCurves.P256
                };

                var cert = ECCertificateBuilder.CreateNewSigningCertificate(options);

                var cng = ECDSACertificateParser.ParsePrivateCertificate(cert);

                Assert.IsNotNull(cng);
            }

            [Test]
            public void NoPublicKeyThrowsError()
            {
                Assert.Throws(typeof(InvalidOperationException), () =>
                {
                    var cert = ECCertificateBuilder.CreateNewSigningCertificate("Test");
                    var data = cert.Export(X509ContentType.Cert);
                    var publicCert = new X509Certificate2(data);

                    ECDSACertificateParser.ParsePrivateCertificate(publicCert);
                });
            }
        }

        [TestFixture]
        public class ParsePublicCertificateMethod : ECCertificateParserTest
        {
            [Test]
            public void P521CertificateCorrectlyParses()
            {
                var options = new ECCertificateBuilderOptions
                {
                    FullSubjectName = "CN=Test",
                    ECCurve = ECNamedCurves.P521
                };

                var cert = ECCertificateBuilder.CreateNewSigningCertificate(options);

                var cng = ECDSACertificateParser.ParsePublicCertificate(cert);

                Assert.IsNotNull(cng);
            }

            [Test]
            public void P384CertificateCorrectlyParses()
            {
                var options = new ECCertificateBuilderOptions
                {
                    FullSubjectName = "CN=Test",
                    ECCurve = ECNamedCurves.P384
                };

                var cert = ECCertificateBuilder.CreateNewSigningCertificate(options);

                var cng = ECDSACertificateParser.ParsePublicCertificate(cert);

                Assert.IsNotNull(cng);
            }

            [Test]
            public void P256CertificateCorrectlyParses()
            {
                var options = new ECCertificateBuilderOptions
                {
                    FullSubjectName = "CN=Test",
                    ECCurve = ECNamedCurves.P256
                };

                var cert = ECCertificateBuilder.CreateNewSigningCertificate(options);

                var cng = ECDSACertificateParser.ParsePublicCertificate(cert);

                Assert.IsNotNull(cng);
            }

            [Test]
            public void PublicKeyOnlyCorrectlyParses()
            {
                var cert = ECCertificateBuilder.CreateNewSigningCertificate("Test");
                var data = cert.Export(X509ContentType.Cert);
                var publicCert = new X509Certificate2(data);

                var cng = ECDSACertificateParser.ParsePublicCertificate(publicCert);
                Assert.IsNotNull(cng);
            }
        }
    }
}
