using System;

namespace Kalix.ApiCrypto.JWT;

/// <summary>
/// Used for JWT verification errors
/// </summary>
public class SignatureVerificationException : Exception
{
    /// <summary>
    /// Exception Constructor
    /// </summary>
    /// <param name="message">Message to set on the exception</param>
    public SignatureVerificationException(string message)
        : base(message)
    {
    }
}