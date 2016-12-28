using System.Collections.Generic;

namespace Kalix.ApiCrypto.JWT.Builder
{
    /// <summary>
    /// The result of the fluent interface decode build function
    /// </summary>
    /// <typeparam name="T">The claim type</typeparam>
    public class JwtDecodeResult<T>
    {
        /// <summary>
        /// The claims encoded in the JWT
        /// </summary>
        public T Claims { get; set; }

        /// <summary>
        /// The complete set of headers in the token
        /// </summary>
        public IDictionary<string, object> Header { get; set; }

        /// <summary>
        /// Whether the token is signed or not
        /// </summary>
        public bool IsSigned { get; set; }

        /// <summary>
        /// Whether the token is signed AND the signature was verified
        /// </summary>
        public bool IsVerified { get; set; }

        /// <summary>
        /// The reason why verification failed (only set if IsVerified == false)
        /// </summary>
        public string VerificationFailedReason { get; set; }

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
