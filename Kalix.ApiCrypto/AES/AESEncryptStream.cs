using System;
using System.IO;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;

namespace Kalix.ApiCrypto.AES;

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
            throw new ArgumentException("Underlying stream is not readable", nameof(data));
        }

        if (!readMode && !data.CanWrite)
        {
            throw new ArgumentException("Underlying stream is not writable", nameof(data));
        }

        _internalStream = data;
        _isRead = readMode;

        var aesProvider = Aes.Create();
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

    public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken ct = default)
    {
        if (_isDisposed) { throw new ObjectDisposedException("AESEncryptStream"); }

        int read = 0;
        var count = buffer.Length;
        var offset = 0;

        if (_initialBytes != null)
        {
            var max = _initialBytes.Length - _initialBytesWritten;
            var length = Math.Min(count, max);
            _initialBytes.AsMemory(_initialBytesWritten, length).CopyTo(buffer.Slice(offset, length));

            read += length;
            offset += length;
            count -= length;
            _initialBytesWritten += length;

            if (_initialBytesWritten >= _initialBytes.Length)
            {
                _initialBytes = null;
            }
        }

        if (count > 0)
        {
            read += await _cryptoStream.ReadAsync(buffer[offset..], ct);
        }

        return read;
    }

    public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken ct)
    {
        return ReadAsync(buffer.AsMemory(offset, count), ct).AsTask();
    }

    public override void Write(byte[] buffer, int offset, int count)
    {
        if (_isDisposed) { throw new ObjectDisposedException("AESEncryptStream"); }

        if(_initialBytes != null)
        {
            _internalStream.Write(_initialBytes, 0, _initialBytes.Length);
            _initialBytes = null;
        }

        _cryptoStream.Write(buffer.AsSpan(offset, count));
    }

    public override async ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken ct = default)
    {
        if (_isDisposed) { throw new ObjectDisposedException("AESEncryptStream"); }

        if (_initialBytes != null)
        {
            await _internalStream.WriteAsync(_initialBytes, ct);
            _initialBytes = null;
        }

        await _cryptoStream.WriteAsync(buffer, ct);
    }

    public override Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken ct)
    {
        return WriteAsync(buffer.AsMemory(offset, count), ct).AsTask();
    }

    public override void Flush()
    {
        if (_isDisposed) { throw new ObjectDisposedException("AESEncryptStream"); }

        _cryptoStream.Flush();
        _internalStream.Flush();
    }

    public override async Task FlushAsync(CancellationToken ct)
    {
        if (_isDisposed) { throw new ObjectDisposedException("AESEncryptStream"); }

        await _cryptoStream.FlushAsync(ct);
        await _internalStream.FlushAsync(ct);
    }

    protected override void Dispose(bool disposing)
    {
        if (disposing && !_isDisposed)
        {
            if(!_isRead && !_cryptoStream.HasFlushedFinalBlock)
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