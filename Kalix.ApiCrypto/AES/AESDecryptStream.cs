﻿using System;
using System.IO;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;

namespace Kalix.ApiCrypto.AES;

/// <summary>
/// Wrapper for a RijndaelManaged AES CrytoStream
/// It expects an IV at the start of the stream before it starts to decrypt
/// </summary>
public class AESDecryptStream : Stream
{
    private readonly Stream _internalStream;
    private readonly bool _leaveOpen;
    private readonly bool _isRead;
    private readonly byte[] _aesKey;

    private CryptoStream _cryptoStream;

    private int _ivLengthBytesWritten;
    private byte[] _ivLengthBytes;

    private int _ivWritten;
    private byte[] _iv;
        
    private bool _isDisposed;

    public AESDecryptStream(byte[] aesKey, Stream data, bool readMode, bool leaveOpen = false)
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
        _leaveOpen = leaveOpen;
        _isRead = readMode;
        _aesKey = aesKey;
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
        if (_isDisposed) { throw new ObjectDisposedException(nameof(AESDecryptStream)); }

        if(_cryptoStream == null)
        {
            var ivLengthBytes = new byte[4];
            var read = _internalStream.Read(ivLengthBytes, 0, 4);
            if(read != 4)
            {
                throw new InvalidOperationException("Stream did not have enough data for IV length");
            }

            var ivLength = BitConverter.ToInt32(ivLengthBytes, 0);
            var iv = new byte[ivLength];
            read = _internalStream.Read(iv, 0, ivLength);
            if (read != ivLength)
            {
                throw new InvalidOperationException("Stream did not have enough data for IV");
            }

            var aesProvider = Aes.Create();
            aesProvider.Key = _aesKey;
            aesProvider.IV = iv;
            var decryptor = aesProvider.CreateDecryptor();
            _cryptoStream = new CryptoStream(_internalStream, decryptor, CryptoStreamMode.Read, _leaveOpen);
        }

        return _cryptoStream.Read(buffer, offset, count);
    }

    public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken ct = default)
    {
        if (_isDisposed) { throw new ObjectDisposedException(nameof(AESDecryptStream)); }

        if (_cryptoStream == null)
        {
            var ivLengthBytes = new byte[4];
            var read = await _internalStream.ReadAsync(ivLengthBytes, ct);
            if (read != 4)
            {
                throw new InvalidOperationException("Stream did not have enough data for IV length");
            }

            var ivLength = BitConverter.ToInt32(ivLengthBytes, 0);
            var iv = new byte[ivLength];
            read = await _internalStream.ReadAsync(iv, ct);
            if (read != ivLength)
            {
                throw new InvalidOperationException("Stream did not have enough data for IV");
            }

            var aesProvider = Aes.Create();
            aesProvider.Key = _aesKey;
            aesProvider.IV = iv;
            var decryptor = aesProvider.CreateDecryptor();
            _cryptoStream = new CryptoStream(_internalStream, decryptor, CryptoStreamMode.Read, _leaveOpen);
        }

        return await _cryptoStream.ReadAsync(buffer, ct);
    }

    public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken ct)
    {
        return ReadAsync(buffer.AsMemory(offset, count), ct).AsTask();
    }

    public override void Write(byte[] buffer, int offset, int count)
    {
        if (_isDisposed) { throw new ObjectDisposedException(nameof(AESDecryptStream)); }

        // Build up internal buffers until we have enough to create crypto stream...
        if(_cryptoStream == null)
        {
            if (_ivLengthBytesWritten != 4)
            {
                if (_ivLengthBytes == null)
                {
                    _ivLengthBytes = new byte[4];
                }

                var length = Math.Min(4 - _ivLengthBytesWritten, count);
                Buffer.BlockCopy(buffer, offset, _ivLengthBytes, _ivLengthBytesWritten, length);

                offset += length;
                count -= length;
                _ivLengthBytesWritten += length;
            }

            if(count > 0 && _ivLengthBytesWritten == 4)
            {
                if(_iv == null)
                {
                    _iv = new byte[BitConverter.ToInt32(_ivLengthBytes, 0)];
                }

                var length = Math.Min(_iv.Length - _ivWritten, count);
                Buffer.BlockCopy(buffer, offset, _iv, _ivWritten, length);

                offset += length;
                count -= length;
                _ivWritten += length;

                if(_ivWritten == _iv.Length)
                {
                    var aesProvider = Aes.Create();
                    aesProvider.Key = _aesKey;
                    aesProvider.IV = _iv;
                    var decryptor = aesProvider.CreateDecryptor();
                    _cryptoStream = new CryptoStream(_internalStream, decryptor, CryptoStreamMode.Write, _leaveOpen);

                    // Free up some memory...
                    _iv = null;
                    _ivLengthBytes = null;
                }
            }
        }

        if (count > 0)
        {
            _cryptoStream.Write(buffer, offset, count);
        }
    }

    public override async ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken ct = default)
    {
        if (_isDisposed) { throw new ObjectDisposedException(nameof(AESDecryptStream)); }

        var count = buffer.Length;
        var offset = 0;

        // Build up internal buffers until we have enough to create crypto stream...
        if (_cryptoStream == null)
        {
            if (_ivLengthBytesWritten != 4)
            {
                if (_ivLengthBytes == null)
                {
                    _ivLengthBytes = new byte[4];
                }

                var length = Math.Min(4 - _ivLengthBytesWritten, count);
                buffer.Slice(offset, length).CopyTo(_ivLengthBytes.AsMemory(_ivLengthBytesWritten, length));

                offset += length;
                count -= length;
                _ivLengthBytesWritten += length;
            }

            if (count > 0 && _ivLengthBytesWritten == 4)
            {
                if (_iv == null)
                {
                    _iv = new byte[BitConverter.ToInt32(_ivLengthBytes, 0)];
                }

                var length = Math.Min(_iv.Length - _ivWritten, count);
                buffer.Slice(offset, length).CopyTo(_iv.AsMemory(_ivWritten, length));

                offset += length;
                count -= length;
                _ivWritten += length;

                if (_ivWritten == _iv.Length)
                {
                    var aesProvider = Aes.Create();
                    aesProvider.Key = _aesKey;
                    aesProvider.IV = _iv;
                    var decryptor = aesProvider.CreateDecryptor();
                    _cryptoStream = new CryptoStream(_internalStream, decryptor, CryptoStreamMode.Write, _leaveOpen);

                    // Free up some memory...
                    _iv = null;
                    _ivLengthBytes = null;
                }
            }
        }

        if (count > 0)
        {
            await _cryptoStream.WriteAsync(buffer[offset..], ct);
        }
    }

    public override Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken ct)
    {
        return WriteAsync(buffer.AsMemory(offset, count), ct).AsTask();
    }

    public override void Flush()
    {
        if (_isDisposed) { throw new ObjectDisposedException(nameof(AESDecryptStream)); }

        if (_cryptoStream != null)
        {
            _cryptoStream.Flush();
        }

        _internalStream.Flush();
    }

    public override async Task FlushAsync(CancellationToken ct)
    {
        if (_isDisposed) { throw new ObjectDisposedException(nameof(AESDecryptStream)); }

        if (_cryptoStream != null)
        {
            await _cryptoStream.FlushAsync(ct);
        }

        await _internalStream.FlushAsync(ct);
    }

    protected override void Dispose(bool disposing)
    {
        if (disposing && !_isDisposed)
        {
            if (_cryptoStream != null)
            {
                if (!_isRead && !_cryptoStream.HasFlushedFinalBlock)
                {
                    _cryptoStream.FlushFinalBlock();
                }

                _cryptoStream.Dispose();
            }
            _isDisposed = true;
        }

        base.Dispose(disposing);
    }

    public override async ValueTask DisposeAsync()
    {
        if (!_isDisposed && _cryptoStream != null)
        {
            if (!_isRead && !_cryptoStream.HasFlushedFinalBlock)
            {
                await _cryptoStream.FlushFinalBlockAsync();
            }

            await _cryptoStream.DisposeAsync();
        }
        _isDisposed = true;
        await base.DisposeAsync();
        GC.SuppressFinalize(this);
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