using Kalix.ApiCrypto.EC;
using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace Kalix.ApiCrypto.JWT.Builder;

/// <summary>
/// The JWT fluent interface encoder
/// </summary>
/// <typeparam name="T">The type of the claims to add</typeparam>
public class JwtEncodeOptions<T>
{
    private readonly T _claims;
    private readonly JwtInternalOptions _options;

    public JwtEncodeOptions(T claims)
    {
        if (claims == null)
        {
            throw new ArgumentNullException(nameof(claims));
        }

        _claims = claims;
        _options = new JwtInternalOptions();
    }

    /// <summary>
    /// This option will add the 'signing' section to the token (3rd part) 
    /// </summary>
    /// <param name="signingCertificate">Certificate to use for signing, must include a private key</param>
    /// <returns>Fluent interface for additional options</returns>
    public JwtEncodeOptions<T> SignUsingECDSA(X509Certificate2 signingCertificate)
    {
        var ecdsa = ECDSACertificateParser.ParsePrivateCertificate(signingCertificate);
        return SignUsingECDSA(ecdsa);
    }

    /// <summary>
    /// This option will add the 'signing' section to the token (3rd part) 
    /// </summary>
    /// <param name="signingCertificate">Certificate to use for signing, must include a private key</param>
    /// <returns>Fluent interface for additional options</returns>
    public JwtEncodeOptions<T> SignUsingECDSA(ECDsa signingCertificate)
    {
        var opts = _options.Clone();
        opts.Certificate = signingCertificate;
        return new JwtEncodeOptions<T>(_claims, opts);
    }

    /// <summary>
    /// Set additional headers in the JWT
    /// Note: The key 'alg' is the only reserved header
    /// </summary>
    /// <param name="headers">Additional headers that will be encoded</param>
    /// <returns>Fluent interface for additional options</returns>
    public JwtEncodeOptions<T> UseAdditionalHeaders(IDictionary<string, object> headers)
    {
        var opts = _options.Clone();
        opts.Headers = headers;
        return new JwtEncodeOptions<T>(_claims, opts);
    }

    /// <summary>
    /// If you need to change the way the header/payload is serialized, you can set that here
    /// </summary>
    /// <param name="settings">The JSON serializer settings to use</param>
    /// <returns>Fluent interface for additional options</returns>
    public JwtEncodeOptions<T> UseJsonSerializerSettings(JsonSerializerSettings settings)
    {
        var opts = _options.Clone();
        opts.JsonSerializerSettings = settings;
        return new JwtEncodeOptions<T>(_claims, opts);
    }

    /// <summary>
    /// Specify the hashing algorithm used during signing
    /// </summary>
    /// <param name="method">The signing algorithm to use</param>
    /// <returns>Fluent interface for additional options</returns>
    public JwtEncodeOptions<T> UseSigningHash(HashingMethods method)
    {
        var opts = _options.Clone();
        opts.SigningHash = method;
        return new JwtEncodeOptions<T>(_claims, opts);
    }

    /// <summary>
    /// This encodes and builds the JWT based on current options
    /// </summary>
    /// <returns>Encode result, including the final JWT</returns>
    public JwtEncodeResult<T> Build()
    {
        var cert = _options.Certificate;
        var headers = new Dictionary<string, object>();
        var serializer = _options.JsonSerializerSettings ?? JsonConvert.DefaultSettings?.Invoke() ?? new JsonSerializerSettings(); // Fallback to the default

        // Copy headers so we don't mess with the original
        if (_options.Headers != null)
        {
            foreach(var h in _options.Headers)
            {
                headers.Add(h.Key, h.Value);
            }
        }

        if (cert != null)
        {
            string signingHashAlg = _options.SigningHash switch
            {
                HashingMethods.Sha256 => "256",
                HashingMethods.Sha384 => "384",
                HashingMethods.Sha512 => "512",
                _ => throw new ArgumentException("Unknown signing hash", nameof(_options.SigningHash)),
            };
            headers["alg"] = $"ES{cert.KeySize}s{signingHashAlg}";
        }

        var segments = new List<string>(cert == null ? 2 : 3);

        var headerJson = JsonConvert.SerializeObject(headers, serializer);
        var headerBytes = Encoding.UTF8.GetBytes(headerJson);
        var payloadJson = JsonConvert.SerializeObject(_claims, serializer);
        var payloadBytes = Encoding.UTF8.GetBytes(payloadJson);

        segments.Add(Base64UrlEncode(headerBytes));
        segments.Add(Base64UrlEncode(payloadBytes));

        if (cert != null)
        {
            var stringToSign = string.Join(".", segments);
            var bytesToSign = Encoding.UTF8.GetBytes(stringToSign);

            var signature = cert.SignData(bytesToSign, _options.SigningHash.ToHashingName());
            segments.Add(Base64UrlEncode(signature));
        }

        var token = string.Join(".", segments);
        return new JwtEncodeResult<T>
        {
            JsonWebToken = token,
            Claims = _claims,
            Header = headers,
            IsSigned = cert != null,
            HeaderJson = headerJson,
            PayloadJson = payloadJson
        };
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

    private JwtEncodeOptions(T claims, JwtInternalOptions options)
    {
        _claims = claims;
        _options = options;
    }

    private class JwtInternalOptions
    {
        public JsonSerializerSettings JsonSerializerSettings { get; set; }
        public IDictionary<string, object> Headers { get; set; }
        public ECDsa Certificate { get; set; }
        public HashingMethods SigningHash { get; set; }

        public JwtInternalOptions()
        {
            SigningHash = HashingMethods.Sha256;
        }

        public JwtInternalOptions Clone()
        {
            return (JwtInternalOptions)MemberwiseClone();
        }
    }
}