using System;
using System.Security.Cryptography;

namespace Kalix.ApiCrypto
{
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
            switch (method)
            {
                case HashingMethods.Sha256:
                    return HashAlgorithmName.SHA256;
                case HashingMethods.Sha384:
                    return HashAlgorithmName.SHA384;
                case HashingMethods.Sha512:
                    return HashAlgorithmName.SHA512;
                default:
                    throw new InvalidOperationException("Selected hashing method is not supported");
            }
        }
    }
}
