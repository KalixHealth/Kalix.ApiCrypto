using System;
using System.IO;
using System.Security.Cryptography;

namespace Kalix.ApiCrypto.AES
{
    /// <summary>
    /// Wrapper for a RijndaelManaged AES CrytoStream
    /// It also auto creates an IV and attaches it to the start of the stream
    /// </summary>
    public class AESEncryptStream : Stream
    {
        private readonly Stream _internalStream;
        private readonly CryptoStream _cryptoStream;
        private readonly bool _isRead;

        private int _initialBytesWritten;
        private byte[] _initialBytes;
        private bool _isDisposed;

        public AESEncryptStream(byte[] aesKey, Stream data, bool readMode)
        {
            if (readMode && !data.CanRead)
            {
                throw new ArgumentException("Underlying stream is not readable", "data");
            }

            if (!readMode && !data.CanWrite)
            {
                throw new ArgumentException("Underlying stream is not writable", "data");
            }

            _internalStream = data;
            _isRead = readMode;

            var aesProvider = new RijndaelManaged();
            aesProvider.Key = aesKey;
            aesProvider.GenerateIV();
            var encryptor = aesProvider.CreateEncryptor();
            _cryptoStream = new CryptoStream(data, encryptor, _isRead ? CryptoStreamMode.Read : CryptoStreamMode.Write);

            _initialBytesWritten = 0;
            _initialBytes = new byte[aesProvider.IV.Length + 4];
            Buffer.BlockCopy(BitConverter.GetBytes(aesProvider.IV.Length), 0, _initialBytes, 0, 4);
            Buffer.BlockCopy(aesProvider.IV, 0, _initialBytes, 4, aesProvider.IV.Length);
        }

        public override bool CanRead
        {
            get { return _isRead; }
        }

        public override bool CanSeek
        {
            get { return false; }
        }

        public override bool CanWrite
        {
            get { return !_isRead; }
        }

        public override int Read(byte[] buffer, int offset, int count)
        {
            if (_isDisposed) { throw new ObjectDisposedException("AESEncryptStream"); }

            int read = 0;
            if(_initialBytes != null)
            {
                var max = _initialBytes.Length - _initialBytesWritten;
                var length = Math.Min(count, max);
                Buffer.BlockCopy(_initialBytes, _initialBytesWritten, buffer, offset, length);

                read += length;
                offset += length;
                count -= length;
                _initialBytesWritten += length;

                if(_initialBytesWritten >= _initialBytes.Length)
                {
                    _initialBytes = null;
                }
            }

            if(count > 0)
            {
                read += _cryptoStream.Read(buffer, offset, count);
            }

            return read;
        }

        public override void Write(byte[] buffer, int offset, int count)
        {
            if (_isDisposed) { throw new ObjectDisposedException("AESEncryptStream"); }

            if(_initialBytes != null)
            {
                _internalStream.Write(_initialBytes, 0, _initialBytes.Length);
                _initialBytes = null;
            }

            _cryptoStream.Write(buffer, offset, count);
        }

        public override void Flush()
        {
            if (_isDisposed) { throw new ObjectDisposedException("AESEncryptStream"); }

            _cryptoStream.Flush();
            _internalStream.Flush();
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing && !_isDisposed)
            {
                if(!_isRead)
                {
                    _cryptoStream.FlushFinalBlock();
                }

                _cryptoStream.Dispose();
                _isDisposed = true;
            }

            base.Dispose(disposing);
        }

        public override long Length
        {
            get { throw new NotImplementedException(); }
        }

        public override long Position
        {
            get
            {
                throw new NotImplementedException();
            }
            set
            {
                throw new NotImplementedException();
            }
        }

        public override long Seek(long offset, SeekOrigin origin)
        {
            throw new NotImplementedException();
        }

        public override void SetLength(long value)
        {
            throw new NotImplementedException();
        }
    }
}
