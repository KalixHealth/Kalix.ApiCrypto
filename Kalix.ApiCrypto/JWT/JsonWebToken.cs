using Kalix.ApiCrypto.EC;
using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

// Heavily inspired by https://github.com/johnsheehan/jwt/blob/master/JWT/JWT.cs
// However modified to work with ECDSA based certificates
namespace Kalix.ApiCrypto.JWT
{
    /// <summary>
    /// Helper library to create JsonWebTokens
    /// For more info see the <a href="http://self-issued.info/docs/draft-ietf-oauth-json-web-token.html">spec</a>
    /// </summary>
    [Obsolete("Should use JwtBuilder now")]
	public static class JsonWebToken
	{
        /// <summary>
        /// Create a web token signed by an ECDSA X509Certificate
        /// </summary>
        /// <param name="claims">JSON serialisable data to be signed</param>
        /// <param name="signingCertificate">Certificate to use for signing, must include a private key</param>
        /// <returns>JWT token</returns>
        public static string EncodeUsingECDSA<T>(T claims, X509Certificate2 signingCertificate)
        {
            string headerJson;
            return EncodeUsingECDSA(claims, signingCertificate, null, null, out headerJson);
        }

        /// <summary>
        /// Create a web token signed by an ECDSA X509Certificate
        /// </summary>
        /// <param name="claims">JSON serialisable data to be signed</param>
        /// <param name="signingCertificate">Certificate to use for signing, must include a private key</param>
        /// <param name="headerJson">[Output] the header json</param>
        /// <returns>JWT token</returns>
        public static string EncodeUsingECDSA<T>(T claims, X509Certificate2 signingCertificate, out string headerJson)
		{
			return EncodeUsingECDSA(claims, signingCertificate, null, null, out headerJson);
		}

		/// <summary>
		/// Create a web token signed by an ECDSA X509Certificate
		/// </summary>
		/// <param name="claims">JSON serialisable data to be signed</param>
		/// <param name="signingCertificate">Certificate to use for signing, must include a private key</param>
		/// <param name="extraHeaderClaims">Extra header params</param>
		/// <param name="serializerSettings"><see cref="JsonSerializerSettings"/> to be used for serialization.</param>
		/// <param name="headerJson">[Output] the header json</param>
		/// <returns>JWT token</returns>
		public static string EncodeUsingECDSA<T>(T claims, X509Certificate2 signingCertificate, IDictionary<string, object> extraHeaderClaims, JsonSerializerSettings serializerSettings, out string headerJson)
		{
			var signer = ECDSACertificateParser.ParsePrivateCertificate(signingCertificate);
			return EncodeUsingECDSA(claims, signer, extraHeaderClaims, serializerSettings, out headerJson);
		}

        /// <summary>
		/// Create a web token signed by an ECDSA certificate, this is the parsed version for increased efficiancy
		/// 
		/// To create the signer <see cref="Kalix.ApiCrypto.EC.ECDSACertificateParser.ParsePrivateCertificate"/>
		/// </summary>
		/// <param name="claims">JSON serialisable data to be signed</param>
		/// <param name="signingCertificate">Certificate data to use for signing</param>
		/// <returns>JWT token</returns>
		public static string EncodeUsingECDSA<T>(T claims, ECDsaCng signingCertificate)
        {
            string headerJson;
            return EncodeUsingECDSA(claims, signingCertificate, null, null, out headerJson);
        }

        /// <summary>
        /// Create a web token signed by an ECDSA certificate, this is the parsed version for increased efficiancy
        /// 
        /// To create the signer <see cref="Kalix.ApiCrypto.EC.ECDSACertificateParser.ParsePrivateCertificate"/>
        /// </summary>
        /// <param name="claims">JSON serialisable data to be signed</param>
        /// <param name="signingCertificate">Certificate data to use for signing</param>
        /// <param name="headerJson">[Output] the header json</param>
        /// <returns>JWT token</returns>
        public static string EncodeUsingECDSA<T>(T claims, ECDsaCng signingCertificate, out string headerJson)
		{
			return EncodeUsingECDSA(claims, signingCertificate, null, null, out headerJson);
		}

		/// <summary>
		/// Create a web token signed by an ECDSA certificate, this is the parsed version for increased efficiancy
		/// 
		/// To create the signer <see cref="Kalix.ApiCrypto.EC.ECDSACertificateParser.ParsePrivateCertificate"/>
		/// </summary>
		/// <param name="claims">JSON serialisable data to be signed</param>
		/// <param name="signingCertificate">Certificate data to use for signing</param>
		/// <param name="extraHeaderClaims">Extra header params</param>
		/// <param name="serializerSettings"><see cref="JsonSerializerSettings"/> to be used for serialization.</param>
		/// <param name="headerJson">[Output] the header json</param>
		/// <returns>JWT token</returns>
		public static string EncodeUsingECDSA<T>(T claims, ECDsaCng signingCertificate, IDictionary<string, object> extraHeaderClaims, JsonSerializerSettings serializerSettings, out string headerJson)
		{
            var result = JwtBuilder.Encode(claims)
                .SignUsingECDSA(signingCertificate)
                .UseAdditionalHeaders(extraHeaderClaims)
                .UseJsonSerializerSettings(serializerSettings)
                .Build();

            headerJson = result.HeaderJson;
            return result.JsonWebToken;
		}

		/// <summary>
		/// Create a web token that is not signed
		/// </summary>
		/// <param name="claims">JSON serialisable data</param>
        /// <param name="headers">Additional headers if required</param>
		/// <returns>JWT token with only 2 parts</returns>
		public static string Encode<T>(T claims, IDictionary<string, object> headers = null)
		{
            var result = JwtBuilder.Encode(claims)
                .UseAdditionalHeaders(headers)
                .Build();

            return result.JsonWebToken;
		}

        /// <summary>
        /// Verify and then parse the data in a JWT
        /// </summary>
        /// <param name="token">The JWT to parse and verify</param>
        /// <param name="verificationCertificate">Public key certificate to verify the token with</param>
        /// <returns>Parsed object data</returns>
        public static T DecodeUsingECDSA<T>(string token, X509Certificate2 verificationCertificate)
        {
            string headerJson;
            string payloadJson;
            return DecodeUsingECDSA<T>(token, verificationCertificate, true, out headerJson, out payloadJson);
        }

        /// <summary>
        /// Verify and then parse the data in a JWT
        /// </summary>
        /// <param name="token">The JWT to parse and verify</param>
        /// <param name="verificationCertificate">Public key certificate to verify the token with</param>
        /// <param name="headerJson">[Output] The header json</param>
        /// <param name="payloadJson">[Output] The payload json</param>
        /// <returns>Parsed object data</returns>
        public static T DecodeUsingECDSA<T>(string token, X509Certificate2 verificationCertificate, out string headerJson, out string payloadJson)
		{
			return DecodeUsingECDSA<T>(token, verificationCertificate, true, out headerJson, out payloadJson);
		}

        /// <summary>
		/// Verify and then parse the data in a JWT
		/// </summary>
		/// <param name="token">The JWT to parse and verify</param>
		/// <param name="verificationCertificate">Public key certificate to verify the token with</param>
		/// <param name="verify">Whether to actually verify the token or not</param>
		/// <returns>Parsed object data</returns>
		public static T DecodeUsingECDSA<T>(string token, X509Certificate2 verificationCertificate, bool verify)
        {
            string headerJson;
            string payloadJson;
            return DecodeUsingECDSA<T>(token, verificationCertificate, verify, out headerJson, out payloadJson);
        }

        /// <summary>
        /// Verify and then parse the data in a JWT
        /// </summary>
        /// <param name="token">The JWT to parse and verify</param>
        /// <param name="verificationCertificate">Public key certificate to verify the token with</param>
        /// <param name="verify">Whether to actually verify the token or not</param>
        /// <param name="headerJson">[Output] The header json</param>
        /// <param name="payloadJson">[Output] The payload json</param>
        /// <returns>Parsed object data</returns>
        public static T DecodeUsingECDSA<T>(string token, X509Certificate2 verificationCertificate, bool verify, out string headerJson, out string payloadJson)
		{
			var verifier = ECDSACertificateParser.ParsePublicCertificate(verificationCertificate);
			return DecodeUsingECDSA<T>(token, verifier, verify, out headerJson, out payloadJson);
		}

        /// <summary>
        /// Verify and then parse the data in a JWT, this is the parsed version for increased efficiancy
        /// 
        /// To create the verifier <see cref="ECDSACertificateParser.ParsePublicCertificate"/>
        /// </summary>
        /// <param name="token">The JWT to parse and verify</param>
        /// <param name="verificationCertificate">Public key certificate to verify the token with</param>
        /// <returns>Parsed object data</returns>
        public static T DecodeUsingECDSA<T>(string token, ECDsaCng verificationCertificate)
        {
            string headerJson;
            string payloadJson;
            return DecodeUsingECDSA<T>(token, verificationCertificate, true, out headerJson, out payloadJson);
        }

        /// <summary>
        /// Verify and then parse the data in a JWT, this is the parsed version for increased efficiancy
        /// 
        /// To create the verifier <see cref="ECDSACertificateParser.ParsePublicCertificate"/>
        /// </summary>
        /// <param name="token">The JWT to parse and verify</param>
        /// <param name="verificationCertificate">Public key certificate to verify the token with</param>
        /// <param name="headerJson">[Output] Header JSON string</param>
        /// <param name="payloadJson">[Output] Payload JSON string</param>
        /// <returns>Parsed object data</returns>
        public static T DecodeUsingECDSA<T>(string token, ECDsaCng verificationCertificate, out string headerJson, out string payloadJson)
		{
			return DecodeUsingECDSA<T>(token, verificationCertificate, true, out headerJson, out payloadJson);
		}

        /// <summary>
		/// Verify and then parse the data in a JWT, this is the parsed version for increased efficiancy
		/// 
		/// To create the verifier <see cref="ECDSACertificateParser.ParsePublicCertificate"/>
		/// </summary>
		/// <param name="token">The JWT to parse and verify</param>
		/// <param name="verificationCertificate">Public key certificate to verify the token with</param>
		/// <param name="verify">Whether to actually verify the token or not</param>
		/// <param name="headerJson">[Output] Header JSON string</param>
		/// <param name="payloadJson">[Output] Payload JSON string</param>
		/// <returns>Parsed object data</returns>
		public static T DecodeUsingECDSA<T>(string token, ECDsaCng verificationCertificate, bool verify)
        {
            string headerJson;
            string payloadJson;
            return DecodeUsingECDSA<T>(token, verificationCertificate, verify, out headerJson, out payloadJson);
        }

        /// <summary>
        /// Verify and then parse the data in a JWT, this is the parsed version for increased efficiancy
        /// 
        /// To create the verifier <see cref="ECDSACertificateParser.ParsePublicCertificate"/>
        /// </summary>
        /// <param name="token">The JWT to parse and verify</param>
        /// <param name="verificationCertificate">Public key certificate to verify the token with</param>
        /// <param name="verify">Whether to actually verify the token or not</param>
        /// <param name="headerJson">[Output] Header JSON string</param>
        /// <param name="payloadJson">[Output] Payload JSON string</param>
        /// <returns>Parsed object data</returns>
        public static T DecodeUsingECDSA<T>(string token, ECDsaCng verificationCertificate, bool verify, out string headerJson, out string payloadJson)
		{
            var result = JwtBuilder.Decode<T>(token)
                .VerifyUsingECDSA(verificationCertificate)
                .Build(verify);

            headerJson = result.HeaderJson;
            payloadJson = result.PayloadJson;
            return result.Claims;
		}
	}
}
