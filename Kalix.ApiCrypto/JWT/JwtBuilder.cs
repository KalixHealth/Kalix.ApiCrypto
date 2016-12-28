using Kalix.ApiCrypto.JWT.Builder;

namespace Kalix.ApiCrypto.JWT
{
    /// <summary>
    /// Start of the fluent interface to build JWT
    /// </summary>
    public static class JwtBuilder
    {
        /// <summary>
        /// The start of encoding/building your own JWT, fluent interface
        /// </summary>
        /// <typeparam name="T">The type object of the claims</typeparam>
        /// <param name="claims">The claims that will be encoded into the JWT</param>
        /// <returns>Fluent interface for additional options</returns>
        public static JwtEncodeOptions<T> Encode<T>(T claims)
        {
            return new JwtEncodeOptions<T>(claims);
        }

        /// <summary>
        /// The start of decoding/verifying your own JWT, fluent interface
        /// </summary>
        /// <typeparam name="T">The type object of the claims</typeparam>
        /// <param name="token">The token to decode/verify</param>
        /// <returns>Fluent interface for additional options</returns>
        public static JwtDecodeOptions<T> Decode<T>(string token)
        {
            return new JwtDecodeOptions<T>(token);
        }
    }
}
