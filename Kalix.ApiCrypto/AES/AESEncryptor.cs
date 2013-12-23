using System;
using System.IO;
using System.Security;

namespace Kalix.ApiCrypto.AES
{
    /// <summary>
    /// This class is designed to be used over and over again for a single key
    /// Will create a new IV per file and save it at the start of the file
    /// </summary>
    public class AESEncryptor
    {
        private readonly int _keySize;
        private readonly string _key;

        public AESEncryptor(AESKeySize keySize, string key)
        {
            switch (keySize)
            {
                case AESKeySize.AES128:
                    _keySize = 128;
                    break;
                case AESKeySize.AES192:
                    _keySize = 192;
                    break;
                case AESKeySize.AES256:
                    _keySize = 256;
                    break;
                default:
                    throw new ArgumentOutOfRangeException("keySize", "Unknown key size");
            }

            _key = key;
        }

        public Stream Encrypt(Stream data, int bufferBytes = 4096)
        {
        }

        public Stream Decrypt(Stream data, int bufferBytes = 4096)
        {
        }

        private class EncryptionStream : Stream
        {
            private readonly Stream _dataStream;

            public EncryptionStream(Stream dataStream)
            {
                _dataStream = dataStream;
            }

            public override int Read(byte[] buffer, int offset, int count)
            {
                throw new NotImplementedException();
            }
        }
    }
}
