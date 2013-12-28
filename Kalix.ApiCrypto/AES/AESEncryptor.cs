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
        /// <param name="data">
        /// Read Mode: Read stream of data to encrypt
        /// Write Mode: A stream to write encrypted data
        /// </param>
        /// <param name="readStream">Specify whether we are in Read Mode or Write Mode, Read mode by default for encryption</param>
        /// <param name="bufferBytes">Chunk size when streaming data</param>
        /// <returns>
        /// Read Mode: Read stream of encrypted data, first set of bytes will contain length of IV (4 bytes), then the IV bytes
        /// Write Mode: A writable stream that will encrypt the data and write it to the underlying stream
        /// </returns>
        public Stream Encrypt(Stream data, bool readMode = true, int bufferBytes = 4096)
        {
            return new EncryptionStream(data, _key, bufferBytes, readMode);
        }

        /// <summary>
        /// Decrypt an encryted stream of data
        /// </summary>
        /// <param name="data">
        /// Read Mode: Read stream of data to decrypt (expected format is 4 bytes which 
        /// corresponds to the IV length, the IV iteself, and then the data to decrypt)
        /// 
        /// Write Mode: A stream to write decrypted data
        /// </param>
        /// <param name="readStream">Specify whether we are in Read Mode or Write Mode, Write mode by default for decryption</param>
        /// <param name="bufferBytes">Chunk size when streaming data</param>
        /// <returns>
        /// Read Mode: Read stream of decrypted data
        /// 
        /// Write Mode: A writable stream that will decrypt the data and write it to the underlying stream 
        /// (when writing to the write stream make sure to start with 4 bytes to indicate IV length, then the IV, then
        /// the data to decrypt)
        /// </returns>
        public Stream Decrypt(Stream data, bool readMode = false, int bufferBytes = 4096)
        {
            return new DecryptionStream(data, _key, bufferBytes, readMode);
        }

        private class EncryptionStream : Stream
        {
            private readonly Stream _dataStream;
            private readonly Stream _underlyingStream;
            private readonly byte[] _initialBytes;
            private readonly bool _readMode;

            private int _position;

            public EncryptionStream(Stream dataStream, byte[] key, int bufferSize, bool readMode)
            {
                _readMode = readMode;

                var aesProvider = new RijndaelManaged();
                aesProvider.Key = key;
                aesProvider.GenerateIV();
                var encryptor = aesProvider.CreateEncryptor();

                // Most efficient to put a buffered stream in the middle
                // This will make sure it will pull data from the underlying stream in chunks (or write in chunks)
                _underlyingStream = new BufferedStream(dataStream, bufferSize);
                _dataStream = new CryptoStream(_underlyingStream, encryptor, _readMode ? CryptoStreamMode.Read : CryptoStreamMode.Write);

                // At the start of our stream encode the IV
                _initialBytes = new byte[aesProvider.IV.Length + 4];
                Buffer.BlockCopy(BitConverter.GetBytes(aesProvider.IV.Length), 0, _initialBytes, 0, 4);
                Buffer.BlockCopy(aesProvider.IV, 0, _initialBytes, 4, aesProvider.IV.Length);

                _position = 0;
            }

            public override bool CanRead
            {
                get { return _readMode; }
            }

            public override bool CanSeek
            {
                get { return false; }
            }

            public override bool CanWrite
            {
                get { return !_readMode; }
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
                if(!_readMode)
                {
                    throw new InvalidOperationException("This is a write stream so cannot be read");
                }

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

            public override void Write(byte[] buffer, int offset, int count)
            {
                if (_readMode)
                {
                    throw new InvalidOperationException("This is a read stream so cannot write");
                }

                // We need to write in our initial bytes
                if(_position == 0)
                {
                    _underlyingStream.Write(_initialBytes, 0, _initialBytes.Length);
                    _position = _initialBytes.Length;
                }

                // Now just write any more bytes into the crypto stream...
                _dataStream.Write(buffer, offset, count);
                _position = _position + count;
            }

            public override void Flush()
            {
                if(_readMode)
                {
                    throw new InvalidOperationException("This is a read stream so cannot flush");
                }

                _dataStream.Flush();
                _underlyingStream.Flush();
            }

            public override void Close()
            {
                base.Close();
                _dataStream.Close();
                _underlyingStream.Close();
            }

            public override long Seek(long offset, SeekOrigin origin)
            {
                throw new NotImplementedException();
            }

            public override void SetLength(long value)
            {
                throw new NotImplementedException();
            }

            public override long Length
            {
                get { throw new NotImplementedException(); }
            }
        }

        private class DecryptionStream : Stream
        {
            private readonly RijndaelManaged _aesProvider;
            private readonly bool _readMode;
            private readonly Stream _underlyingStream;

            private Stream _dataStream;
            private byte[] _initialBytes; // write stream buffer
            private int _ivLength; // write stream storage
            private int _position;

            public DecryptionStream(Stream dataStream, byte[] key, int bufferSize, bool readMode)
            {
                _readMode = readMode;
                _aesProvider = new RijndaelManaged();
                _aesProvider.Key = key;

                // Most efficient to put a buffered stream in the middle
                _underlyingStream = new BufferedStream(dataStream, bufferSize);
                _position = 0;

                if (!readMode)
                {
                    _initialBytes = new byte[4];
                    _ivLength = 0;
                }
            }

            public override bool CanRead
            {
                get { return _readMode; }
            }

            public override bool CanSeek
            {
                get { return false; }
            }

            public override bool CanWrite
            {
                get { return !_readMode; }
            }

            public override void Flush()
            {
                if (_readMode)
                {
                    throw new InvalidOperationException("This is a read stream so cannot flush");
                }

                if (_dataStream != null)
                {
                    _dataStream.Flush();
                }
                _underlyingStream.Flush();
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
                if (!_readMode)
                {
                    throw new InvalidOperationException("This is a write stream so cannot be read");
                }

                // Read the first couple bytes to setup the cryptostream
                if (_dataStream == null)
                {
                    var IVlengthBytes = new byte[4];
                    if (_underlyingStream.Read(IVlengthBytes, 0, 4) != 4)
                    {
                        throw new InvalidOperationException("Stream was not long enough - not enough bytes for the IV length");
                    }

                    var IVlength = BitConverter.ToInt32(IVlengthBytes, 0);

                    var IV = new byte[IVlength];
                    if (_underlyingStream.Read(IV, 0, IVlength) != IVlength)
                    {
                        throw new InvalidOperationException("Stream was not long enough - not enough bytes for the IV");
                    }

                    _aesProvider.IV = IV;
                    var decryptor = _aesProvider.CreateDecryptor();
                    _dataStream = new CryptoStream(_underlyingStream, decryptor, CryptoStreamMode.Read);
                }

                // Reading from a cryptostream at this point
                var bytesRead = _dataStream.Read(buffer, offset, count);
                _position = _position + bytesRead;
                return bytesRead;
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
                if (_readMode)
                {
                    throw new InvalidOperationException("This is a read stream so cannot be written to");
                }

                // Calculate length of IV
                var intBytesLength = 4 - _position;
                if(intBytesLength > 0)
                {
                    if (intBytesLength > count) { intBytesLength = count; }
                    Buffer.BlockCopy(buffer, offset, _initialBytes, _position, intBytesLength);
                    offset = offset + intBytesLength;
                    count = count - intBytesLength;
                    _position = _position + intBytesLength;

                    if(_position == 4)
                    {
                        _ivLength = BitConverter.ToInt32(_initialBytes, 0);
                        _initialBytes = new byte[_ivLength];
                    }
                }

                // Get the IV
                var ivBytesLength = 4 + _ivLength - _position;
                if (count > 0 && ivBytesLength > 0)
                {
                    if (ivBytesLength > count) { ivBytesLength = count; }
                    Buffer.BlockCopy(buffer, offset, _initialBytes, _position - 4, ivBytesLength);
                    offset = offset + ivBytesLength;
                    count = count - ivBytesLength;
                    _position = _position + ivBytesLength;

                    // We finally have the IV, change the data stream to match
                    if(_position == 4 + _ivLength)
                    {
                        _aesProvider.IV = _initialBytes;
                        var decryptor = _aesProvider.CreateDecryptor();
                        _dataStream = new CryptoStream(_underlyingStream, decryptor, CryptoStreamMode.Write);
                    }
                }

                if (count > 0)
                {
                    if (_dataStream == null)
                    {
                        throw new InvalidOperationException("Format incorrect, could not setup the crypto stream as IV data was missing");
                    }

                    // Start writing directly from the buffer into the crytostream
                    _dataStream.Write(buffer, offset, count);
                    _position = _position + count;
                }
            }

            // Close all the streams that belong to this class
            public override void Close()
            {
                base.Close();
                if(_dataStream != null)
                {
                    _dataStream.Close();
                }
                _underlyingStream.Close();
            }
        }
    }
}
