using System.Collections.Generic;
using Kalix.ApiCrypto.EC;
using Kalix.ApiCrypto.JWT;
using NUnit.Framework;

namespace Kalix.ApiCrypto.Tests.JWT
{
    [TestFixture]
    public class JsonWebTokenTests
    {
        [Test]
        public void HeaderAndPayloadParsesCorrectly()
        {
			var options = new ECCertificateBuilderOptions
			{
				ECCurve = ECNamedCurves.P256,
				FullSubjectName = "CN=Test"
			};
			var cert = ECCertificateBuilder.CreateNewSigningCertificate(options);
	        var token = JsonWebToken.EncodeUsingECDSA(new {id = 1, org = 1}, cert,
		        new Dictionary<string, object> {{"alg", "ES256"}});
            var bits = token.Split('.');

            Assert.AreEqual(3, bits.Length);
            Assert.AreEqual("eyJhbGciOiJFUzI1NiJ9", bits[0]);  // HEADER
            Assert.AreEqual("eyJpZCI6MSwib3JnIjoxfQ", bits[1]); // DATA
        }

        [Test]
        public void ParseBackAndForthWorks()
        {
			var options = new ECCertificateBuilderOptions
			{
				ECCurve = ECNamedCurves.P256,
				FullSubjectName = "CN=Test"
			};
			var cert = ECCertificateBuilder.CreateNewSigningCertificate(options);

			var token = JsonWebToken.EncodeUsingECDSA(new { id = 1, org = 2 }, cert, new Dictionary<string, object> { { "alg", "ES256" } });
            dynamic result = JsonWebToken.DecodeUsingECDSA<object>(token, cert);

            Assert.AreEqual(1, (int)result.id);
            Assert.AreEqual(2, (int)result.org);
        }

        [Test]
        public void WrongCertificateThrowsError()
        {
			var options = new ECCertificateBuilderOptions
			{
				ECCurve = ECNamedCurves.P256,
				FullSubjectName = "CN=Test"
			};
			var cert = ECCertificateBuilder.CreateNewSigningCertificate(options);
			var token = JsonWebToken.EncodeUsingECDSA(new { id = 1, org = 2 }, cert, new Dictionary<string, object> { { "alg", "ES256" } });

			options = new ECCertificateBuilderOptions
			{
				ECCurve = ECNamedCurves.P256,
				FullSubjectName = "CN=Test"
			};
			cert = ECCertificateBuilder.CreateNewSigningCertificate(options);

            try
            {
                JsonWebToken.DecodeUsingECDSA<object>(token, cert);
            }
            catch (SignatureVerificationException ex)
            {
                Assert.AreEqual("Invalid signature.", ex.Message);
                return;
            }

            Assert.Fail();
        }

        [Test]
        public void ECDSAKeySizeDoesNotMatchThrowsError()
        {
	        var options = new ECCertificateBuilderOptions
	        {
		        FullSubjectName = "CN=Test",
		        ECCurve = ECNamedCurves.P521,
		        HashingMethod = HashingMethods.Sha256,
		        ECKeyName = "ECDSA_Test" 
	        };
			var cert = ECCertificateBuilder.CreateNewSigningCertificate(options);
			var token = JsonWebToken.EncodeUsingECDSA(new { id = 1, org = 2 }, cert, new Dictionary<string, object> { { "alg", "ES521" } });

            cert = ECCertificateBuilder.CreateNewSigningCertificate(new ECCertificateBuilderOptions { ECCurve = ECNamedCurves.P256, FullSubjectName = "CN=Test" });

            try
            {
                JsonWebToken.DecodeUsingECDSA<object>(token, cert);
            }
            catch (SignatureVerificationException ex)
            {
                Assert.AreEqual("Key size does not match.", ex.Message);
                return;
            }

            Assert.Fail();
        }

        [Test]
        public void UnknownJWTAlgorithmThrowsError()
        {
			var options = new ECCertificateBuilderOptions
			{
				ECCurve = ECNamedCurves.P256,

				FullSubjectName = "CN=Test"
			};
			var cert = ECCertificateBuilder.CreateNewSigningCertificate(options);
			var token = JsonWebToken.EncodeUsingECDSA(new { id = 1, org = 2 }, cert, new Dictionary<string, object> { { "alg", "ES256" } });
            var split = token.Split('.');
            split[0] = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSU0EifQ";  // switch header
            token = string.Join(".", split);

            try
            {
                JsonWebToken.DecodeUsingECDSA<object>(token, cert);
            }
            catch (SignatureVerificationException ex)
            {
                Assert.AreEqual("Unsupported signing algorithm.", ex.Message);
                return;
            }

            Assert.Fail();
        }
    }
}
