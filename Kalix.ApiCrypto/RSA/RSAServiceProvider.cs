using Security.Cryptography;
using System.IO;
using System.Security.Cryptography;

namespace Kalix.ApiCrypto.RSA
{
    /// <summary>
    /// A wrapper library to match the RSACryptoServiceProvider when using the Cng based private key
    /// Helps to avoid exposing the internal RSACng class
    /// </summary>
    public class RSAServiceProvider : System.Security.Cryptography.RSA
    {
        private readonly RSACng _key;

        internal RSAServiceProvider(RSACng key)
        {
            _key = key;
        }

        /// <summary>
        /// Sets the hash algorithm to use when encrypting or decrypting data using the
        /// OAEP padding method. This property is only used if data is encrypted or decrypted
        /// and the EncryptionPaddingMode is set to AsymmetricEncryptionPaddingMode.Oaep.
        /// The default value is Sha256.
        /// </summary>
        /// <exception cref="System.ArgumentNullException">
        /// if EncryptionHashAlgorithm is set to null
        /// </exception>
        public CngAlgorithm EncryptionHashAlgorithm
        {
            get { return _key.EncryptionHashAlgorithm; }
            set { _key.EncryptionHashAlgorithm = value; }
        }

        /// <summary>
        /// Sets the padding mode to use when encrypting or decrypting data. The default
        /// value is AsymmetricPaddingMode.Oaep.
        /// </summary>
        /// <exception cref="System.ArgumentNullException">
        /// if EncryptionPaddingMOde is set to null
        /// </exception>
        public AsymmetricPaddingMode EncryptionPaddingMode
        {
            get { return (AsymmetricPaddingMode)_key.EncryptionPaddingMode; }
            set { _key.EncryptionPaddingMode = (Security.Cryptography.AsymmetricPaddingMode)value; }
        }

        /// <summary>
        /// Gets the key that will be used by the RSA object for any cryptographic operation
        /// that it uses.  This key object will be disposed if the key is reset, for
        /// instance by changing the KeySize property, using ImportParamers to create
        /// a new key, or by Disposing of the parent RSA object.  Therefore, you should
        /// make sure that the key object is no longer used in these scenarios. This
        /// object will not be the same object as the CngKey passed to the RSACng constructor
        /// if that constructor was used, however it will point at the same CNG key.
        /// </summary>
        public CngKey Key { get { return _key.Key; } }

        /// <summary>
        /// Returns "RSA-PKCS1-KeyEx". This property should not be used.
        /// </summary>
        public override string KeyExchangeAlgorithm { get { return _key.KeyExchangeAlgorithm; } }

        /// <summary>
        /// Key storage provider being used for the algorithm
        /// </summary>
        public CngProvider Provider { get { return _key.Provider; } }

        /// <summary>
        /// Returns "http://www.w3.org/2000/09/xmldsig#rsa-sha1". This property should
        /// not be used.
        /// </summary>
        public override string SignatureAlgorithm { get { return _key.SignatureAlgorithm; } }

        /// <summary>
        /// Gets or sets the hash algorithm to use when signing or verifying data. The
        /// default value is Sha256.
        /// </summary>
        /// <exception cref="System.ArgumentNullException">
        /// if SignatureHashAlgorithm is set to null
        /// </exception>
        public CngAlgorithm SignatureHashAlgorithm
        {
            get { return _key.SignatureHashAlgorithm; }
            set { _key.SignatureHashAlgorithm = value; }
        }

        /// <summary>
        /// Gets or sets the padding mode to use when encrypting or decrypting data.
        /// The default value is AsymmetricPaddingMode.Pkcs1.
        /// </summary>
        /// <exception cref="System.ArgumentOutOfRangeException">
        /// if SignaturePaddingMode is set to a mode other than Pkcs1 or Pss
        /// </exception>
        public AsymmetricPaddingMode SignaturePaddingMode
        {
            get { return (AsymmetricPaddingMode)_key.SignaturePaddingMode; }
            set { _key.SignaturePaddingMode = (Security.Cryptography.AsymmetricPaddingMode)value; }
        }

        /// <summary>
        /// Gets or sets the number of bytes of salt to use when signing data or verifying
        /// a signature using the PSS padding mode. This property is only used if data
        /// is being signed or verified and the SignaturePaddingMode is set to AsymmetricEncryptionPaddingMode.Pss.
        /// The default value is 20 bytes.
        /// </summary>
        /// <exception cref="System.ArgumentOutOfRangeException">
        /// if SignatureSaltBytes is set to a negative number
        /// </exception>
        public int SignatureSaltBytes
        {
            get { return _key.SignatureSaltBytes; }
            set { _key.SignatureSaltBytes = value; }
        }

        /// <summary>
        /// DecryptValue decrypts the input data using the padding mode specified in
        /// the EncryptionPaddingMode property. The return value is the decrypted data.
        /// </summary>
        /// <param name="rgb">encrypted data to decrypt</param>
        /// <exception cref="System.ArgumentNullException">if rgb is null</exception>
        /// <exception cref="System.Security.Cryptography.CryptographicException">if rgb could not be decrypted</exception>
        public override byte[] DecryptValue(byte[] rgb)
        {
            return _key.DecryptValue(rgb);
        }

        /// <summary>
        /// EncryptValue encrypts the input data using the padding mode specified in
        /// the EncryptionPaddingMode property. The return value is the encrypted data.
        /// </summary>
        /// <param name="rgb">data to encrypt</param>
        /// <exception cref="System.ArgumentNullException">if rgb is null</exception>
        /// <exception cref="System.Security.Cryptography.CryptographicException">if rgb could not be decrypted</exception>
        public override byte[] EncryptValue(byte[] rgb)
        {
            return _key.EncryptValue(rgb);
        }

        /// <summary>
        /// Exports the key used by the RSA object into an RSAParameters object.
        /// </summary>
        public override RSAParameters ExportParameters(bool includePrivateParameters)
        {
            return _key.ExportParameters(includePrivateParameters);
        }

        /// <summary>
        /// ImportParameters will replace the existing key that RSACng is working with
        /// by creating a new CngKey for the parameters structure. If the parameters
        /// structure contains only an exponent and modulus, then only a public key will
        /// be imported. If the parameters also contain P and Q values, then a full key
        /// pair will be imported.
        /// The default KSP used by RSACng does not support importing full RSA key pairs
        /// on Windows Vista. If the ImportParameters method is called with a full key
        /// pair, the operation will fail with a CryptographicException stating that
        /// the operation was invalid. Other KSPs may have similar restrictions. To work
        /// around this, make sure to only import public keys when using the default
        /// KSP.
        /// </summary>
        /// <exception cref="System.ArgumentException">if parameters contains neither an exponent nor a modulus</exception>
        /// <exception cref="System.Security.Cryptography.CryptographicException">
        /// if parameters is not a valid RSA key or if parameters is a full key pair
        /// and the default KSP is used
        /// </exception>
        public override void ImportParameters(RSAParameters parameters)
        {
            _key.ImportParameters(parameters);
        }

        /// <summary>
        /// SignData signs the given data after hashing it with the SignatureHashAlgorithm
        /// algorithm.
        /// </summary>
        /// <param name="data">data to sign</param>
        /// <exception cref="System.ArgumentNullException">if data is null</exception>
        /// <exception cref="System.Security.Cryptography.CryptographicException">if data could not be signed</exception>
        /// <exception cref="System.InvalidOperationException">if SignatureHashAlgorithm is not MD5, SHA-1, SHA-256, SHA-384, or SHA-512</exception>
        public byte[] SignData(byte[] data)
        {
            return _key.SignData(data);
        }

        /// <summary>
        /// SignData signs the given data after hashing it with the SignatureHashAlgorithm
        /// algorithm.
        /// </summary>
        /// <param name="data">data to sign</param>
        /// <exception cref="System.ArgumentNullException">if data is null</exception>
        /// <exception cref="System.Security.Cryptography.CryptographicException">if data could not be signed</exception>
        /// <exception cref="System.InvalidOperationException">if SignatureHashAlgorithm is not MD5, SHA-1, SHA-256, SHA-384, or SHA-512</exception>
        public byte[] SignData(Stream data)
        {
            return _key.SignData(data);
        }

        /// <summary>
        /// SignData signs the given data after hashing it with the SignatureHashAlgorithm
        /// algorithm.
        /// </summary>
        /// <param name="data">data to sign</param>
        /// <param name="offset">offset into the data that the signature should begin covering</param>
        /// <param name="count">number of bytes to include in the signed data</param>
        /// <exception cref="System.ArgumentNullException">if data is null</exception>
        /// <exception cref="System.ArgumentOutOfRangeException">if offset or count are negative, or if count specifies more bytes than are available in data.</exception>
        /// <exception cref="System.Security.Cryptography.CryptographicException">if data could not be signed</exception>
        /// <exception cref="System.InvalidOperationException">if SignatureHashAlgorithm is not MD5, SHA-1, SHA-256, SHA-384, or SHA-512</exception>
        public byte[] SignData(byte[] data, int offset, int count)
        {
            return _key.SignData(data, offset, count);
        }

        /// <summary>
        /// Sign data which was hashed using the SignatureHashAlgorithm; if the algorithm
        /// used to hash the data was different, use the SignHash(byte[], CngAlgorithm)
        /// overload instead.
        /// </summary>
        /// <param name="hash">hash to sign</param>
        /// <exception cref="System.ArgumentNullException">if hash is null</exception>
        /// <exception cref="System.Security.Cryptography.CryptographicException">if data could not be signed</exception>
        /// <exception cref="System.InvalidOperationException">if SignatureHashAlgorithm is not MD5, SHA-1, SHA-256, SHA-384, or SHA-512</exception>
        public byte[] SignHash(byte[] hash)
        {
            return _key.SignHash(hash);
        }

        /// <summary>
        /// Sign already hashed data, specifying the algorithm it was hashed with. This
        /// method does not use the SignatureHashAlgorithm property.
        /// </summary>
        /// <param name="hash">hash to sign</param>
        /// <param name="hashAlgorithm">algorithm hash was signed with</param>
        /// <exception cref="System.ArgumentNullException">if hash or hashAlgorithm are null</exception>
        /// <exception cref="System.Security.Cryptography.CryptographicException">if data could not be signed</exception>
        public byte[] SignHash(byte[] hash, CngAlgorithm hashAlgorithm)
        {
            return _key.SignHash(hash, hashAlgorithm);
        }

        /// <summary>
        /// VerifyData verifies that the given signature matches given data after hashing
        /// it with the SignatureHashAlgorithm algorithm.
        /// </summary>
        /// <param name="data">data to verify</param>
        /// <param name="signature">signature of the data</param>
        /// <returns>true if the signature verifies for the data, false if it does not</returns>
        /// <exception cref="System.ArgumentNullException">if data or signature are null</exception>
        /// <exception cref="System.InvalidOperationException">if SignatureHashAlgorithm is not MD5, SHA-1, SHA-256, SHA-384, or SHA-512</exception>
        public bool VerifyData(byte[] data, byte[] signature)
        {
            return _key.VerifyData(data, signature);
        }

        /// <summary>
        /// VerifyData verifies that the given signature matches given data after hashing
        /// it with the SignatureHashAlgorithm algorithm.
        /// </summary>
        /// <param name="data">data to verify</param>
        /// <param name="signature">signature of the data</param>
        /// <returns>true if the signature verifies for the data, false if it does not</returns>
        /// <exception cref="System.ArgumentNullException">if data or signature are null</exception>
        /// <exception cref="System.InvalidOperationException">if SignatureHashAlgorithm is not MD5, SHA-1, SHA-256, SHA-384, or SHA-512</exception>
        public bool VerifyData(Stream data, byte[] signature)
        {
            return _key.VerifyData(data, signature);
        }

        /// <summary>
        /// VerifyData verifies that the given signature matches given data after hashing
        /// it with the SignatureHashAlgorithm algorithm.
        /// </summary>
        /// <param name="data">data to verify</param>
        /// <param name="offset">offset into the data that the signature should begin covering</param>
        /// <param name="count">number of bytes to include in the signed data</param>
        /// <param name="signature">signature of the data</param>
        /// <returns>true if the signature verifies for the data, false if it does not</returns>
        /// <exception cref="System.ArgumentNullException">if data or signature are null</exception>
        /// <exception cref="System.ArgumentOutOfRangeException">if offset or count are negative, or if count specifies more bytes than are available in data.</exception>
        /// <exception cref="System.InvalidOperationException">if SignatureHashAlgorithm is not MD5, SHA-1, SHA-256, SHA-384, or SHA-512</exception>
        public bool VerifyData(byte[] data, int offset, int count, byte[] signature)
        {
            return _key.VerifyData(data, offset, count, signature);
        }

        /// <summary>
        /// Verify data which was signed and already hashed with the SignatureHashAlgorithm;
        /// if a different hash algorithm was used to hash the data use the VerifyHash(byte[],
        /// byte[], CngAlgorithm) overload instead.
        /// </summary>
        /// <param name="hash">hash to verify</param>
        /// <param name="signature">signature of the data</param>
        /// <returns>true if the signature verifies for the hash, false if it does not</returns>
        /// <exception cref="System.ArgumentNullException">if hash or signature are null</exception>
        /// <exception cref="System.InvalidOperationException">if SignatureHashAlgorithm is not MD5, SHA-1, SHA-256, SHA-384, or SHA-512</exception>
        public bool VerifyHash(byte[] hash, byte[] signature)
        {
            return _key.VerifyHash(hash, signature);
        }

        /// <summary>
        /// Verify data which was signed and hashed with the given hash algorithm. This
        /// overload does not use the SignatureHashAlgorithm property.
        /// </summary>
        /// <param name="hash">hash to verify</param>
        /// <param name="signature">signature of the data</param>
        /// <param name="hashAlgorithm">algorithm that hash was hashed with</param>
        /// <returns>true if the signature verifies for the hash, false if it does not</returns>
        /// <exception cref="System.ArgumentNullException">if hash, signature, or hashAlgorithm are null</exception>
        public bool VerifyHash(byte[] hash, byte[] signature, CngAlgorithm hashAlgorithm)
        {
            return _key.VerifyHash(hash, signature, hashAlgorithm);
        }

        protected override void Dispose(bool disposing)
        {
            _key.Dispose();
        }
    }
}
