using Security.Cryptography.X509Certificates;
using System;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace Kalix.ApiCrypto.EC
{
    /// <summary>
    /// Helper class to parse ECDSA based X509Certificates using the newer Cng libraries
    /// </summary>
    public static class ECDSACertificateParser
    {
        private const string P256OID = "1.2.840.10045.3.1.7";
        private const string P384OID = "1.3.132.0.34";
        private const string P521OID = "1.3.132.0.35";

        /// <summary>
        /// Parses the certificate to get access to the underlying ECDsaCng implementation
        /// Requires the private key so that the resulting ECDsaCng can sign
        /// </summary>
        /// <param name="certificate">A certificate from a file or store</param>
        /// <returns>ECDsaCng that can sign AND verify data</returns>
        public static ECDsaCng ParsePrivateCertificate(X509Certificate2 certificate)
        {
            // Get the ECDSA private key (needs CngKey lib)
            var privateKey = certificate.GetCngPrivateKey();
            if (privateKey == null)
            {
                throw new InvalidOperationException("Certificate does not contain a private key, or is not in the right format");
            }

            return new ECDsaCng(privateKey);
        }

        /// <summary>
        /// Parses the certificate to get access to the underlying ECDsaCng implementation
        /// Only requires the public key
        /// </summary>
        /// <param name="certificate">A certificate from a file or store</param>
        /// <returns>ECDsaCng that can verify data only</returns>
        public static ECDsaCng ParsePublicCertificate(X509Certificate2 certificate)
        {
            // Code pulled from https://github.com/juhovh/AaltoTLS/blob/master/Plugins/EllipticCurveCipherSuitePlugin/SignatureAlgorithmECDSA.cs
            // and modified slightly...
            byte[] keyData = certificate.PublicKey.EncodedKeyValue.RawData;
            if (keyData[0] != 0x04)
            {
                throw new Exception("Only uncompressed ECDSA keys supported, format: " + keyData[0]);
            }

            string curveOid = DER2OID(certificate.PublicKey.EncodedParameters.RawData);
            if (curveOid == null)
            {
                throw new Exception("Unsupported ECDSA public key parameters");
            }

            UInt32 keyLength;
            byte[] blobMagic;
            if (curveOid.Equals(P256OID))
            {
                keyLength = 32;
                blobMagic = Encoding.ASCII.GetBytes("ECS1");
            }
            else if (curveOid.Equals(P384OID))
            {
                keyLength = 48;
                blobMagic = Encoding.ASCII.GetBytes("ECS3");
            }
            else if (curveOid.Equals(P521OID))
            {
                keyLength = 66;
                blobMagic = Encoding.ASCII.GetBytes("ECS5");
            }
            else
            {
                throw new Exception("Unsupported ECC curve type OID: " + curveOid);
            }

            if (2 * keyLength != keyData.Length - 1)
            {
                throw new Exception("Invalid length of ECDSA public key: " + keyData.Length + " (should be " + (1 + 2 * keyLength) + ")");
            }

            byte[] lengthData = BitConverter.GetBytes(keyLength);

            // Create the ECC public blob for ECDsaCng class
            byte[] eccBlob = new byte[8 + 2 * keyLength];
            Buffer.BlockCopy(blobMagic, 0, eccBlob, 0, 4);
            Buffer.BlockCopy(lengthData, 0, eccBlob, 4, 4);
            Buffer.BlockCopy(keyData, 1, eccBlob, 8, (int)(2 * keyLength));

            var publicKey = CngKey.Import(eccBlob, CngKeyBlobFormat.EccPublicBlob);
            return new ECDsaCng(publicKey);
        }

        private static string DER2OID(byte[] oid)
        {
            try
            {
                if (oid[0] != 0x06 || oid[1] >= 128 || oid[1] != oid.Length - 2)
                {
                    return null;
                }

                byte firstByte = oid[2];
                string ret = (firstByte / 40) + "." + (firstByte % 40) + ".";
                for (int i = 3; i < oid.Length; i++)
                {
                    if (oid[i] < 128)
                    {
                        ret += (int)oid[i];
                    }
                    else if (oid[i] >= 128 && oid[i + 1] < 128)
                    {
                        ret += (int)(((oid[i] & 0x7f) << 7) | oid[i + 1]);
                        i++;
                    }
                    else
                    {
                        return null;
                    }

                    if (i != oid.Length - 1)
                    {
                        ret += ".";
                    }
                }
                return ret;
            }
            catch (Exception)
            {
                return null;
            }
        }
    }
}
