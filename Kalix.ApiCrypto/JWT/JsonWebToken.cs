using Kalix.ApiCrypto.EC;
using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace Kalix.ApiCrypto.JWT
{
    // Heavily inspired by https://github.com/johnsheehan/jwt/blob/master/JWT/JWT.cs
    // However modified to work with ECDSA based certificates
    public static class JsonWebToken
    {
        public static string EncodeUsingECDSA<T>(T claims, X509Certificate2 signingCertificate)
        {
            var signer = ECCertificateParser.ParsePrivateCertificate(signingCertificate);
            return EncodeUsingECDSA(claims, signer);
        }

        public static string EncodeUsingECDSA<T>(T claims, ECDsaCng signer)
        {
            var segments = new List<string>();
            var header = new { typ = "JWT", alg = "ES" + signer.KeySize };

            byte[] headerBytes = Encoding.UTF8.GetBytes(JsonConvert.SerializeObject(header));
            byte[] payloadBytes = Encoding.UTF8.GetBytes(JsonConvert.SerializeObject(claims));

            segments.Add(Base64UrlEncode(headerBytes));
            segments.Add(Base64UrlEncode(payloadBytes));

            var stringToSign = string.Join(".", segments.ToArray());
            var bytesToSign = Encoding.UTF8.GetBytes(stringToSign);

            byte[] signature = signer.SignData(bytesToSign);
            segments.Add(Base64UrlEncode(signature));

            return string.Join(".", segments.ToArray());
        }

        public static T DecodeUsingECDSA<T>(string token, X509Certificate2 verificationCertificate, bool verify = true)
        {
            var verifier = ECCertificateParser.ParsePublicCertificate(verificationCertificate);
            return DecodeUsingECDSA<T>(token, verifier, verify);
        }

        public static T DecodeUsingECDSA<T>(string token, ECDsaCng verifier, bool verify = true)
        {
            var parts = token.Split('.');
            var header = parts[0];
            var payload = parts[1];
            
            if (verify)
            {
                var headerDetails = JsonConvert.DeserializeObject<IDictionary<string, string>>(Encoding.UTF8.GetString(Base64UrlDecode(header)));
                if (!headerDetails.ContainsKey("alg") || !headerDetails["alg"].StartsWith("ES"))
                {
                    throw new SignatureVerificationException(string.Format("Unsupported signing algorithm."));
                }

                if (verifier.KeySize.ToString() != headerDetails["alg"].Substring(2))
                {
                    throw new SignatureVerificationException(string.Format("Key size does not match."));
                }

                var compare = Encoding.UTF8.GetBytes(string.Concat(header, ".", payload));
                byte[] signature = Base64UrlDecode(parts[2]);

                if (!verifier.VerifyData(compare, signature))
                {
                    throw new SignatureVerificationException(string.Format("Invalid signature."));
                }
            }

            var payloadJson = Encoding.UTF8.GetString(Base64UrlDecode(payload));
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
                default: throw new System.Exception("Illegal base64url string!");
            }
            var converted = Convert.FromBase64String(output); // Standard base64 decoder
            return converted;
        }
    }
}
