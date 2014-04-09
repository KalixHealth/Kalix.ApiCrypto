namespace Kalix.ApiCrypto.EC
{
    /// <summary>
    /// EC Named Curves supported by the Cng library
    /// These are in the list of NIST recommended curves 
    /// </summary>
    public enum ECNamedCurves
    {
        /// <summary>
        /// 521 bit 'Fp' curve
        /// </summary>
        P521,
        /// <summary>
        /// 384 bit 'Fp' curve
        /// </summary>
        P384,
        /// <summary>
        /// 256 bit 'Fp' curve
        /// </summary>
        P256
    }
}
