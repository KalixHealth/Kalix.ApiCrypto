using System;
using System.IO;
using System.Security.Cryptography;

namespace Kalix.ApiCrypto.AES
{
    /// <summary>
    /// This class is designed to be used over and over again for a single key
    /// Will create a new IV per file and save it at the start of the file
    /// </summary>
    public class AESEncryptor
    {
        private readonly byte[] _key;

        /// <summary>
        /// Create the encyptor using an AES key
        /// </summary>
        /// <param name="key">Must be a valid AES key</param>
        public AESEncryptor(byte[] key)
        {
            _key = key;
        }

        /// <summary>
        /// Encrypt a stream of data
        /// 
        /// As per best practise creates a new IV for every record encryted, this IV is exported in the stream along with
        /// the encrypted data
        /// </summary>
        /// <param name="data">Data to encrypt</param>
        /// <param name="bufferBytes">Chunk size when streaming data</param>
        /// <returns>Read stream of encrypted data, first set of bytes will contain length of IV (4 bytes), then the IV bytes</returns>
        public Stream Encrypt(Stream data, int bufferBytes = 4096)
        {
            return new EncryptionStream(data, _key, bufferBytes);
        }

        /// <summary>
        /// Decrypt an encryted stream of data
        /// </summary>
        /// <param name="data">Data to decrypt, expected format as per Encrypt</param>
        /// <param name="bufferBytes">Chunk size when streaming data</param>
        /// <returns>Read stream of original data</returns>
        public Stream Decrypt(Stream data, int bufferBytes = 4096)
        {
            return new DecryptionStream(data, _key, bufferBytes);
        }

        private class EncryptionStream : Stream
        {
            private readonly Stream _dataStream;
            private readonly byte[] _initialBytes;

            private int _position;

            public EncryptionStream(Stream dataStream, byte[] key, int bufferSize)
            {
                var aesProvider = new RijndaelManaged();
                aesProvider.Key = key;
                aesProvider.GenerateIV();
                var encryptor = aesProvider.CreateEncryptor();

                // Most efficient to put a buffered stream in the middle
                // This will make sure it will pull data from the underlying stream in chunks
                _dataStream = new CryptoStream(new BufferedStream(dataStream, bufferSize), encryptor, CryptoStreamMode.Read);

                // At the start of our stream encode the IV
                _initialBytes = new byte[aesProvider.IV.Length + 4];
                Buffer.BlockCopy(BitConverter.GetBytes(aesProvider.IV.Length), 0, _initialBytes, 0, 4);
                Buffer.BlockCopy(aesProvider.IV, 0, _initialBytes, 4, aesProvider.IV.Length);

                _position = 0;
            }

            public override bool CanRead
            {
                get { return true; }
            }

            public override bool CanSeek
            {
                get { return false; }
            }

            public override bool CanWrite
            {
                get { return false; }
            }

            public override void Flush()
            {
                throw new NotImplementedException();
            }

            public override long Length
            {
                get { throw new NotImplementedException(); }
            }

            public override long Position
            {
                get
                {
                    return _position;
                }
                set
                {
                    throw new NotImplementedException();
                }
            }

            public override int Read(byte[] buffer, int offset, int count)
            {
                var copiedBytes = 0;
                var initialBytes = _initialBytes.Length - _position;
                if (initialBytes > count)
                {
                    initialBytes = count;
                }

                if (initialBytes > 0)
                {
                    Buffer.BlockCopy(_initialBytes, _position, buffer, offset, initialBytes);
                    offset = offset + initialBytes;
                    count = count - initialBytes;
                    copiedBytes = initialBytes;
                }

                if (count > 0)
                {
                    copiedBytes = copiedBytes + _dataStream.Read(buffer, offset, count);
                }

                _position = _position + copiedBytes;
                return copiedBytes;
            }

            public override long Seek(long offset, SeekOrigin origin)
            {
                throw new NotImplementedException();
            }

            public override void SetLength(long value)
            {
                throw new NotImplementedException();
            }

            public override void Write(byte[] buffer, int offset, int count)
            {
                throw new NotImplementedException();
            }
        }

        private class DecryptionStream : Stream
        {
            private readonly RijndaelManaged _aesProvider;

            private Stream _dataStream;
            private bool _hasLoaded;

            public DecryptionStream(Stream dataStream, byte[] key, int bufferSize)
            {
                _aesProvider = new RijndaelManaged();
                _aesProvider.Key = key;

                // Most efficient to put a buffered stream in the middle
                _dataStream = new BufferedStream(dataStream, bufferSize);
                _hasLoaded = false;
            }

            public override bool CanRead
            {
                get { return true; }
            }

            public override bool CanSeek
            {
                get { return false; }
            }

            public override bool CanWrite
            {
                get { return false; }
            }

            public override void Flush()
            {
                throw new NotImplementedException();
            }

            public override long Length
            {
                get { throw new NotImplementedException(); }
            }

            public override long Position
            {
                get
                {
                    return _hasLoaded ? _dataStream.Position : 0;
                }
                set
                {
                    throw new NotImplementedException();
                }
            }

            public override int Read(byte[] buffer, int offset, int count)
            {
                // Read the first couple bytes to setup the cryptostream
                if (!_hasLoaded)
                {
                    var IVlengthBytes = new byte[4];
                    if (_dataStream.Read(IVlengthBytes, 0, 4) != 4)
                    {
                        throw new InvalidOperationException("Stream was not long enough - not enough bytes for the IV length");
                    }

                    var IVlength = BitConverter.ToInt32(IVlengthBytes, 0);

                    var IV = new byte[IVlength];
                    if (_dataStream.Read(IV, 0, IVlength) != IVlength)
                    {
                        throw new InvalidOperationException("Stream was not long enough - not enough bytes for the IV");
                    }

                    _aesProvider.IV = IV;
                    var decryptor = _aesProvider.CreateDecryptor();
                    _dataStream = new CryptoStream(_dataStream, decryptor, CryptoStreamMode.Read);
                    _hasLoaded = true;
                }

                // Reading from a cryptostream at this point
                return _dataStream.Read(buffer, offset, count);
            }

            public override long Seek(long offset, SeekOrigin origin)
            {
                throw new NotImplementedException();
            }

            public override void SetLength(long value)
            {
                throw new NotImplementedException();
            }

            public override void Write(byte[] buffer, int offset, int count)
            {
                throw new NotImplementedException();
            }
        }
    }
}
