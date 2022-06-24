using Kalix.ApiCrypto.EC;
using Kalix.ApiCrypto.JWT;
using NUnit.Framework;

namespace Kalix.ApiCrypto.Tests.JWT;

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
            
        var token = JwtBuilder.Encode(new { id = 1, org = 1 })
            .SignUsingECDSA(cert)
            .Build();

        var bits = token.JsonWebToken.Split('.');

        Assert.AreEqual(3, bits.Length);
        Assert.AreEqual("eyJhbGciOiJFUzI1NnMyNTYifQ", bits[0]);  // HEADER
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
            
        var token = JwtBuilder.Encode(new {id = 1, org = 2})
            .SignUsingECDSA(cert)
            .Build();

        var result = JwtBuilder.Decode<dynamic>(token.JsonWebToken)
            .VerifyUsingECDSA(cert)
            .Build();

        Assert.AreEqual(1, (int)result.Claims.id);
        Assert.AreEqual(2, (int)result.Claims.org);
            
        Assert.IsFalse(string.IsNullOrWhiteSpace(result.HeaderJson));
        Assert.IsTrue(string.Equals(token.HeaderJson, result.HeaderJson));
        Assert.IsFalse(string.IsNullOrWhiteSpace(result.PayloadJson));
            

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
        var token = JwtBuilder.Encode(new {id = 1, org = 2})
            .SignUsingECDSA(cert)
            .Build();

        options = new ECCertificateBuilderOptions
        {
            ECCurve = ECNamedCurves.P256,
            FullSubjectName = "CN=Test"
        };
        cert = ECCertificateBuilder.CreateNewSigningCertificate(options);

        try
        {
            JwtBuilder.Decode<object>(token.JsonWebToken)
                .VerifyUsingECDSA(cert)
                .Build();
        }
        catch (SignatureVerificationException ex)
        {
            Assert.AreEqual("Token does not match signature", ex.Message);
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
            HashingMethod = HashingMethods.Sha256
        };
        var cert = ECCertificateBuilder.CreateNewSigningCertificate(options);
        var token = JwtBuilder.Encode(new {id = 1, org = 2})
            .SignUsingECDSA(cert)
            .Build();

        cert = ECCertificateBuilder.CreateNewSigningCertificate(new ECCertificateBuilderOptions { ECCurve = ECNamedCurves.P256, FullSubjectName = "CN=Test" });

        try
        {
            JwtBuilder.Decode<object>(token.JsonWebToken)
                .VerifyUsingECDSA(cert)
                .Build();
        }
        catch (SignatureVerificationException ex)
        {
            Assert.AreEqual("Key size does not match: ES256 vs ES521", ex.Message);
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
        var token = JwtBuilder.Encode(new {id = 1, org = 2})
            .SignUsingECDSA(cert)
            .Build()
            .JsonWebToken;

        var split = token.Split('.');
        split[0] = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSU0EifQ";  // switch header
        token = string.Join(".", split);

        try
        {
            JwtBuilder.Decode<object>(token)
                .VerifyUsingECDSA(cert)
                .Build();
        }
        catch (SignatureVerificationException ex)
        {
            Assert.AreEqual("Unsupported signing algorithm: RSA", ex.Message);
            return;
        }

        Assert.Fail();
    }
}