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
        Sha256,
        /// <summary>
        /// 160 bit SHA-1
        /// </summary>
        Sha1
    }
}
