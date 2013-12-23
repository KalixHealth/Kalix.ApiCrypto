namespace Kalix.ApiCrypto
{
    /// <summary>
    /// Padding modes
    /// </summary>
    public enum AsymmetricPaddingMode
    {
        /// <summary>
        /// No padding
        /// </summary>
        None = 1,
        /// <summary>
        /// PKCS #1 padding
        /// </summary>
        Pkcs1 = 2,
        /// <summary>
        /// Optimal Asymmetric Encryption Padding
        /// </summary>
        Oaep = 4,
        /// <summary>
        /// Probabilistic Signature Scheme padding
        /// </summary>
        Pss = 8,
    }
}
