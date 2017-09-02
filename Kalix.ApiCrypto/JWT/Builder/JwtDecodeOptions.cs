using Kalix.ApiCrypto.EC;
using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace Kalix.ApiCrypto.JWT.Builder
{
    /// <summary>
    /// The JWT fluent interface decoder
    /// </summary>
    /// <typeparam name="T">The type that the claims will be decoded to</typeparam>
    public class JwtDecodeOptions<T>
    {
        private readonly string _token;
        private readonly JwtInternalOptions _options;

        public JwtDecodeOptions(string token)
        {
            if (string.IsNullOrWhiteSpace(token))
            {
                throw new ArgumentNullException("token");
            }

            var parts = token.Split('.');
            if (parts.Length != 2 && parts.Length != 3)
            {
                throw new ArgumentException("Invalid JWT, does not have 2 or 3 parts", "token");
            }

            _token = token;
            _options = new JwtInternalOptions();
        }

        /// <summary>
        /// This option will be used to verify the token (needs 3 part token) 
        /// </summary>
        /// <param name="verificationCertificate">Public key certificate to verify the token with</param>
        /// <returns>Fluent interface for additional options</returns>
        public JwtDecodeOptions<T> VerifyUsingECDSA(X509Certificate2 verificationCertificate)
        {
            var ecdsa = ECDSACertificateParser.ParsePublicCertificate(verificationCertificate);
            return VerifyUsingECDSA(ecdsa);
        }

        /// <summary>
        /// This option will be used to verify the token (needs 3 part token)
        /// </summary>
        /// <param name="verificationCertificate">Public key certificate to verify the token with</param>
        /// <returns>Fluent interface for additional options</returns>
        public JwtDecodeOptions<T> VerifyUsingECDSA(ECDsa verificationCertificate)
        {
            var opts = _options.Clone();
            opts.Certificate = verificationCertificate;
            return new JwtDecodeOptions<T>(_token, opts);
        }

        /// <summary>
        /// If you need to change the way the header/payload is serialized, you can set that here
        /// </summary>
        /// <param name="settings">The JSON serializer settings to use</param>
        /// <returns>Fluent interface for additional options</returns>
        public JwtDecodeOptions<T> UseJsonSerializerSettings(JsonSerializerSettings settings)
        {
            var opts = _options.Clone();
            opts.JsonSerializerSettings = settings;
            return new JwtDecodeOptions<T>(_token, opts);
        }

        /// <summary>
        /// This decodes the JWT based on current options
        /// </summary>
        /// <param name="throwIfNotValid">If true will throw a <see cref="SignatureVerificationException"/> if the token is not signed or does not pass</param>
        /// <returns>Decode result</returns>
        public JwtDecodeResult<T> Build(bool throwIfNotValid = true)
        {
            var serializer = _options.JsonSerializerSettings ?? JsonConvert.DefaultSettings?.Invoke() ?? new JsonSerializerSettings(); // Fallback to the default

            var parts = _token.Split('.');
            var headerPart = parts[0];
            var payloadPart = parts[1];

            var headerJson = Encoding.UTF8.GetString(Base64UrlDecode(headerPart));
            var headers = JsonConvert.DeserializeObject<IDictionary<string, object>>(headerJson, serializer);

            var isSigned = parts.Length == 3;
            bool isVerified;
            string verificationResult;

            if (isSigned)
            {
                verificationResult = Verify(headers, _options.Certificate, headerPart, payloadPart, parts[2]);
                isVerified = verificationResult == null;
            }
            else
            {
                verificationResult = "JWT does not have 3 parts";
                isVerified = false;
            }

            if (throwIfNotValid && !isVerified)
            {
                throw new SignatureVerificationException(verificationResult);
            }

            var payloadJson = Encoding.UTF8.GetString(Base64UrlDecode(payloadPart));
            var claims = JsonConvert.DeserializeObject<T>(payloadJson, serializer);

            return new JwtDecodeResult<T>
            {
                Claims = claims,
                Header = headers,
                IsSigned = isSigned,
                IsVerified = isVerified,
                VerificationFailedReason = verificationResult,
                HeaderJson = headerJson,
                PayloadJson = payloadJson
            };
        }

        private string Verify(IDictionary<string, object> headers, ECDsa cert, string headerPart, string payloadPart, string signature)
        {
            if (cert == null)
            {
                return "No certificate was provided to check the JWT against";
            }

            string alg;
            if (!headers.ContainsKey("alg") || string.IsNullOrWhiteSpace(alg = headers["alg"] as string))
            {
                return "Signing algorith was not specified in 'alg' property";
            }

            if (!alg.StartsWith("ES"))
            {
                return $"Unsupported signing algorithm: {alg}";
            }

            var shaParts = alg.Substring(2).Split('s');
            if (cert.KeySize.ToString() != shaParts[0])
            {
                return $"Key size does not match: ES{cert.KeySize} vs ES{shaParts[0]}";
            }

            HashingMethods hashMethod = HashingMethods.Sha256;
            if (shaParts.Length == 2)
            {
                switch(shaParts[1])
                {
                    case "256":
                        hashMethod = HashingMethods.Sha256;
                        break;
                    case "384":
                        hashMethod = HashingMethods.Sha384;
                        break;
                    case "512":
                        hashMethod = HashingMethods.Sha512;
                        break;
                    default:
                        return $"Unknown signing sha value {shaParts[1]}";
                }
            }

            var compare = Encoding.UTF8.GetBytes(string.Concat(headerPart, ".", payloadPart));
            var signatureBytes = Base64UrlDecode(signature);

            if (!cert.VerifyData(compare, signatureBytes, hashMethod.ToHashingName()))
            {
                return "Token does not match signature";
            }

            return null;
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

        private JwtDecodeOptions(string token, JwtInternalOptions options)
        {
            _token = token;
            _options = options;
        }

        private class JwtInternalOptions
        {
            public JsonSerializerSettings JsonSerializerSettings { get; set; }
            public ECDsa Certificate { get; set; }

            public JwtInternalOptions Clone()
            {
                return (JwtInternalOptions)MemberwiseClone();
            }
        }
    }
}
