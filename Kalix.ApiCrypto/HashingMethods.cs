using System;
using System.Security.Cryptography;

namespace Kalix.ApiCrypto;

/// <summary>
/// Hashing method for signing
/// </summary>
public enum HashingMethods
{
    /// <summary>
    /// 512 bit SHA-2
    /// </summary>
    Sha512,
    /// <summary>
    /// 384 bit SHA-2
    /// </summary>
    Sha384,
    /// <summary>
    /// 256 bit SHA-2
    /// </summary>
    Sha256
}

public static class HashingMethodsExtensions
{
    public static HashAlgorithmName ToHashingName(this HashingMethods method)
    {
        return method switch
        {
            HashingMethods.Sha256 => HashAlgorithmName.SHA256,
            HashingMethods.Sha384 => HashAlgorithmName.SHA384,
            HashingMethods.Sha512 => HashAlgorithmName.SHA512,
            _ => throw new InvalidOperationException("Selected hashing method is not supported"),
        };
    }
}