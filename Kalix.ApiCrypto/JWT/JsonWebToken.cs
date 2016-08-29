using Kalix.ApiCrypto.EC;
using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

// Heavily inspired by https://github.com/johnsheehan/jwt/blob/master/JWT/JWT.cs
// However modified to work with ECDSA based certificates
namespace Kalix.ApiCrypto.JWT
{
	/// <summary>
	/// Helper library to create JsonWebTokens
	/// For more info see the <a href="http://self-issued.info/docs/draft-ietf-oauth-json-web-token.html">spec</a>
	/// </summary>
	public static class JsonWebToken
	{
		/// <summary>
		/// Create a web token signed by an ECDSA X509Certificate
		/// </summary>
		/// <param name="claims">JSON serialisable data to be signed</param>
		/// <param name="signingCertificate">Certificate to use for signing, must include a private key</param>
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
		/// <param name="payloadSerializerSettings"><see cref="JsonSerializerSettings"/> to be used for <paramref name="claims"/> serialization.</param>
		/// <param name="headerJson">[Output] the header json</param>
		/// <param name="payloadJson">[Output] the payload json</param>
		/// <returns>JWT token</returns>
		public static string EncodeUsingECDSA<T>(T claims,X509Certificate2 signingCertificate,IDictionary<string, object> extraHeaderClaims,JsonSerializerSettings payloadSerializerSettings, out string headerJson)
		{
			var signer = ECDSACertificateParser.ParsePrivateCertificate(signingCertificate);
			return EncodeUsingECDSA(claims, signer, extraHeaderClaims, payloadSerializerSettings, out headerJson);
		}

		/// <summary>
		/// Create a web token signed by an ECDSA certificate, this is the parsed version for increased efficiancy
		/// 
		/// To create the signer <see cref="Kalix.ApiCrypto.EC.ECDSACertificateParser.ParsePrivateCertificate"/>
		/// </summary>
		/// <param name="claims">JSON serialisable data to be signed</param>
		/// <param name="signingCertificate">Certificate data to use for signing</param>
		/// <param name="extraHeaderClaims">Extra header params</param>
		/// <param name="payloadSerializerSettings"><see cref="JsonSerializerSettings"/> to be used for <paramref name="claims"/> serialization.</param>
		/// <param name="headerJson">[Output] the header json</param>
		/// <param name="payloadJson">[Output] the payload json</param>
		/// <returns>JWT token</returns>
		public static string EncodeUsingECDSA<T>(T claims,ECDsaCng signingCertificate, out string headerJson)
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
		/// <param name="payloadSerializerSettings"><see cref="JsonSerializerSettings"/> to be used for <paramref name="claims"/> serialization.</param>
		/// <param name="headerJson">[Output] the header json</param>
		/// <param name="payloadJson">[Output] the payload json</param>
		/// <returns>JWT token</returns>
		public static string EncodeUsingECDSA<T>(T claims,ECDsaCng signingCertificate,IDictionary<string, object> extraHeaderClaims,JsonSerializerSettings payloadSerializerSettings, out string headerJson)
		{
			if (claims == null)
				throw new ArgumentNullException("claims");

			if (extraHeaderClaims == null)
				extraHeaderClaims = new Dictionary<string, object>();

			extraHeaderClaims["alg"] = string.Format("ES{0}", signingCertificate.KeySize);

			if (payloadSerializerSettings == null)
				payloadSerializerSettings = new JsonSerializerSettings();

			var segments = new List<string>(3);

			headerJson = JsonConvert.SerializeObject(extraHeaderClaims, payloadSerializerSettings);
			var headerBytes = Encoding.UTF8.GetBytes(headerJson);
			var payloadJson = JsonConvert.SerializeObject(claims, payloadSerializerSettings);
			var payloadBytes = Encoding.UTF8.GetBytes(payloadJson);

			segments.Add(Base64UrlEncode(headerBytes));
			segments.Add(Base64UrlEncode(payloadBytes));

			var stringToSign = string.Join(".", segments);
			var bytesToSign = Encoding.UTF8.GetBytes(stringToSign);

			var signature = signingCertificate.SignData(bytesToSign);
			segments.Add(Base64UrlEncode(signature));

			return string.Join(".", segments);
		}

		/// <summary>
		/// Create a web token that is not signed
		/// </summary>
		/// <param name="claims">JSON serialisable data</param>
		/// <returns>JWT token with only 2 parts</returns>
		public static string Encode<T>(T claims, IDictionary<string, object> header)
		{
			var segments = new List<string>();

			var headerBytes = Encoding.UTF8.GetBytes(JsonConvert.SerializeObject(header));
			var payloadBytes = Encoding.UTF8.GetBytes(JsonConvert.SerializeObject(claims));

			segments.Add(Base64UrlEncode(headerBytes));
			segments.Add(Base64UrlEncode(payloadBytes));

			return string.Join(".", segments.ToArray());
		}

		/// <summary>
		/// Verify and then parse the data in a JWT
		/// </summary>
		/// <param name="token">The JWT to parse and verify</param>
		/// <param name="verificationCertificate">Public key certificate to verify the token with</param>
		/// <param name="headerJson">[Output] The header json</param>
		/// <param name="payloadJson">[Output] The payload json</param>
		/// <returns>Parsed object data</returns>
		public static T DecodeUsingECDSA<T>(string token, X509Certificate2 verificationCertificate, out string headerJson,
			out string payloadJson)
		{
			return DecodeUsingECDSA<T>(token, verificationCertificate, true, out headerJson, out payloadJson);
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
		/// To create the verifier <see cref="Kalix.ApiCrypto.EC.ECDSACertificateParser.ParsePublicCertificate"/>
		/// </summary>
		/// <param name="token">The JWT to parse and verify</param>
		/// <param name="verificationCertificate">Public key certificate to verify the token with</param>
		/// <param name="headerJson">[Output] Header JSON string</param>
		/// <param name="payloadJson">[Output] Payload JSON string</param>
		/// <returns>Parsed object data</returns>
		public static T DecodeUsingECDSA<T>(string token, ECDsaCng verificationCertificate, out string headerJson,
			out string payloadJson)
		{
			return DecodeUsingECDSA<T>(token, verificationCertificate, true, out headerJson, out payloadJson);
		}

		/// <summary>
		/// Verify and then parse the data in a JWT, this is the parsed version for increased efficiancy
		/// 
		/// To create the verifier <see cref="Kalix.ApiCrypto.EC.ECDSACertificateParser.ParsePublicCertificate"/>
		/// </summary>
		/// <param name="token">The JWT to parse and verify</param>
		/// <param name="verificationCertificate">Public key certificate to verify the token with</param>
		/// <param name="verify">Whether to actually verify the token or not</param>
		/// <param name="headerJson">[Output] Header JSON string</param>
		/// <param name="payloadJson">[Output] Payload JSON string</param>
		/// <returns>Parsed object data</returns>
		public static T DecodeUsingECDSA<T>(string token, ECDsaCng verificationCertificate, bool verify, out string headerJson, out string payloadJson)
		{
			var parts = token.Split('.');
			var header = parts[0];
			var payload = parts[1];

			headerJson = Encoding.UTF8.GetString(Base64UrlDecode(header));

			if (verify)
			{
				var headerDetails = JsonConvert.DeserializeObject<IDictionary<string, string>>(headerJson);

				if (!headerDetails.ContainsKey("alg") || !headerDetails["alg"].StartsWith("ES"))
				{
					throw new SignatureVerificationException(string.Format("Unsupported signing algorithm."));
				}

				if (verificationCertificate.KeySize.ToString() != headerDetails["alg"].Substring(2))
				{
					throw new SignatureVerificationException(string.Format("Key size does not match."));
				}

				var compare = Encoding.UTF8.GetBytes(string.Concat(header, ".", payload));
				var signature = Base64UrlDecode(parts[2]);

				if (!verificationCertificate.VerifyData(compare, signature))
				{
					throw new SignatureVerificationException(string.Format("Invalid signature."));
				}
			}

			payloadJson = Encoding.UTF8.GetString(Base64UrlDecode(payload));

			return JsonConvert.DeserializeObject<T>(payloadJson);
		}

		// from JWT spec
		private static string Base64UrlEncode(byte[] input)
		{
			var output = Convert.ToBase64String(input);
			output = output.Split('=')[0]; // Remove any trailing '='s
			output = output.Replace('+', '-'); // 62nd char of encoding
			output = output.Replace('/', '_'); // 63rd char of encoding
			return output;
		}

		// from JWT spec
		private static byte[] Base64UrlDecode(string input)
		{
			var output = input;
			output = output.Replace('-', '+'); // 62nd char of encoding
			output = output.Replace('_', '/'); // 63rd char of encoding
			switch (output.Length % 4) // Pad with trailing '='s
			{
				case 0: break; // No pad chars in this case
				case 2: output += "=="; break; // Two pad chars
				case 3: output += "="; break; // One pad char
				default:
					throw new ArgumentException("Illegal base64url string!", "input");
			}
			var converted = Convert.FromBase64String(output); // Standard base64 decoder
			return converted;
		}
	}
}
