using System.IO;

namespace Kalix.ApiCrypto.AES;

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
    /// Encrypt a chunk of data
    /// 
    /// As per best practise creates a new IV for every record encryted, this IV is exported in the output along with
    /// the encrypted data
    /// </summary>
    /// <param name="data">Data that will be encrypted</param>
    /// <returns>Encrypted data, first chunks will contain length of IV (4 bytes), then the IV bytes</returns>
    public byte[] Encrypt(byte[] data)
    {
        using var ms = new MemoryStream();
        using (var aes = new AESEncryptStream(_key, ms, false))
        {
            aes.Write(data, 0, data.Length);
        }

        return ms.ToArray();
    }

    /// <summary>
    /// Decrypt an chunk of data
    /// </summary>
    /// <param name="data">
    /// Data that you want to decrypt (expected format is 4 bytes which 
    /// corresponds to the IV length, the IV iteself, and then the data to decrypt)
    /// </param>
    /// <returns>Decrypted data</returns>
    public byte[] Decrypt(byte[] data)
    {
        using var ms = new MemoryStream();
        using (var aes = new AESDecryptStream(_key, ms, false))
        {
            aes.Write(data, 0, data.Length);
        }

        return ms.ToArray();
    }

    /// <summary>
    /// Encrypt a stream of data
    /// 
    /// As per best practise creates a new IV for every record encryted, this IV is exported in the stream along with
    /// the encrypted data
    /// </summary>
    /// <param name="data">Read/Write stream to wrap for encryption</param>
    /// <param name="readMode">Are we wrapping a read stream, true for read stread, false for write stream</param>
    /// <returns>Read/Write stream of encrypted data, first chunks will contain length of IV (4 bytes), then the IV bytes</returns>
    public Stream Encrypt(Stream data, bool readMode)
    {
        return new AESEncryptStream(_key, data, readMode);
    }

    /// <summary>
    /// Decrypt an encryted stream of data
    /// </summary>
    /// <param name="data">
    /// Read/Write stream to wrap for decryption (expected format is 4 bytes which 
    /// corresponds to the IV length, the IV iteself, and then the data to decrypt)
    /// </param>
    /// <param name="readMode">Are we wrapping a read stream, true for read stread, false for write stream</param>
    /// <returns>Read/Write stream of decrypted data</returns>
    public Stream Decrypt(Stream data, bool readMode)
    {
        return new AESDecryptStream(_key, data, readMode);
    }
}