﻿using Kalix.ApiCrypto.RSA;
using NUnit.Framework;
using System;
using System.Security.Cryptography.X509Certificates;

namespace Kalix.ApiCrypto.Tests.RSA;

[TestFixture]
public class RSACertificateParserTest
{
    [TestFixture]
    public class ParsePrivateCertificateMethod : RSACertificateParserTest
    {
        [Test]
        public void KeySize4096CertificateCorrectlyParses()
        {
            var options = new RSACertificateBuilderOptions
            {
                FullSubjectName = "CN=Test",
                KeySize = 4096
            };

            var cert = RSACertificateBuilder.CreateNewCertificate(options);
            var cng = RSACertificateParser.ParsePrivateCertificate(cert);

            Assert.That(cng, Is.Not.Null);
        }

        [Test]
        public void KeySize2048CertificateCorrectlyParses()
        {
            var options = new RSACertificateBuilderOptions
            {
                FullSubjectName = "CN=Test",
                KeySize = 2048
            };

            var cert = RSACertificateBuilder.CreateNewCertificate(options);
            var cng = RSACertificateParser.ParsePrivateCertificate(cert);

            Assert.That(cng, Is.Not.Null);
        }

        [Test]
        public void KeySize7168CertificateCorrectlyParses()
        {
            var options = new RSACertificateBuilderOptions
            {
                FullSubjectName = "CN=Test",
                KeySize = 7168
            };

            var cert = RSACertificateBuilder.CreateNewCertificate(options);
            var cng = RSACertificateParser.ParsePrivateCertificate(cert);

            Assert.That(cng, Is.Not.Null);
        }

        [Test]
        public void NoPublicKeyThrowsError()
        {
            Assert.Throws<InvalidOperationException>(() =>
            {
                var cert = RSACertificateBuilder.CreateNewCertificate("Test");
                var data = cert.Export(X509ContentType.Cert);
                var publicCert = X509CertificateLoader.LoadCertificate(data);

                RSACertificateParser.ParsePrivateCertificate(publicCert);
            });
        }
    }

    [TestFixture]
    public class ParsePublicCertificateMethod : RSACertificateParserTest
    {
        [Test]
        public void KeySize4096CertificateCorrectlyParses()
        {
            var options = new RSACertificateBuilderOptions
            {
                FullSubjectName = "CN=Test",
                KeySize = 4096
            };

            var cert = RSACertificateBuilder.CreateNewCertificate(options);
            var cng = RSACertificateParser.ParsePublicCertificate(cert);

            Assert.That(cng, Is.Not.Null);
        }

        [Test]
        public void KeySize2048CertificateCorrectlyParses()
        {
            var options = new RSACertificateBuilderOptions
            {
                FullSubjectName = "CN=Test",
                KeySize = 2048
            };

            var cert = RSACertificateBuilder.CreateNewCertificate(options);
            var cng = RSACertificateParser.ParsePublicCertificate(cert);

            Assert.That(cng, Is.Not.Null);
        }

        [Test]
        public void KeySize7168CertificateCorrectlyParses()
        {
            var options = new RSACertificateBuilderOptions
            {
                FullSubjectName = "CN=Test",
                KeySize = 7168
            };

            var cert = RSACertificateBuilder.CreateNewCertificate(options);
            var cng = RSACertificateParser.ParsePublicCertificate(cert);

            Assert.That(cng, Is.Not.Null);
        }

        [Test]
        public void PublicKeyOnlyCorrectlyParses()
        {
            var cert = RSACertificateBuilder.CreateNewCertificate("Test");
            var data = cert.Export(X509ContentType.Cert);
            var publicCert = X509CertificateLoader.LoadCertificate(data);

            var cng = RSACertificateParser.ParsePublicCertificate(publicCert);
            Assert.That(cng, Is.Not.Null);
        }
    }
}