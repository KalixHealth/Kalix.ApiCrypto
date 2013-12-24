using System;

namespace Kalix.ApiCrypto.JWT
{
    /// <summary>
    /// Used for JWT verification errors
    /// </summary>
    public class SignatureVerificationException : Exception
    {
        public SignatureVerificationException(string message)
            : base(message)
        {
        }
    }
}
