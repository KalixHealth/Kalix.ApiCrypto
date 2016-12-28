using System.Collections.Generic;

namespace Kalix.ApiCrypto.JWT.Builder
{
    /// <summary>
    /// The result of the fluent interface encode build function
    /// </summary>
    /// <typeparam name="T">The claim type</typeparam>
    public class JwtEncodeResult<T>
    {
        /// <summary>
        /// The built JWT
        /// </summary>
        public string JsonWebToken { get; set; }

        /// <summary>
        /// The claims used to build the JWT
        /// </summary>
        public T Claims { get; set; }

        /// <summary>
        /// The complete set of headers used in the token
        /// </summary>
        public IDictionary<string, object> Header { get; set; }

        /// <summary>
        /// Whether the token is signed or not
        /// </summary>
        public bool IsSigned { get; set; }

        /// <summary>
        /// If required, access to the header string created during the process
        /// </summary>
        public string HeaderJson { get; set; }

        /// <summary>
        /// If required, access to the payload string created during the process
        /// </summary>
        public string PayloadJson { get; set; }
    }
}
