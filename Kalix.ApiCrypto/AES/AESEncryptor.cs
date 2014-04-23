using System;
using System.IO;
using System.Reactive.Linq;
using System.Security.Cryptography;
using System.Linq;

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
        /// <param name="data">Observable stream of data to encrypt</param>
        /// <returns>Observable stream of encrypted data, first chunks will contain length of IV (4 bytes), then the IV bytes</returns>
        public IObservable<byte[]> Encrypt(IObservable<byte[]> data)
        {
            return Observable.Create<byte[]>(obs =>
            {
                var aesProvider = new RijndaelManaged();
                aesProvider.Key = _key;
                aesProvider.GenerateIV();
                var encryptor = aesProvider.CreateEncryptor();
                bool hasFinished = false;

                // First chunk is IV info
                var initialBytes = new byte[aesProvider.IV.Length + 4];
                Buffer.BlockCopy(BitConverter.GetBytes(aesProvider.IV.Length), 0, initialBytes, 0, 4);
                Buffer.BlockCopy(aesProvider.IV, 0, initialBytes, 4, aesProvider.IV.Length);
                obs.OnNext(initialBytes);

                return BufferBytes(data, encryptor.InputBlockSize)
                    .Subscribe((d) =>
                    {
                        var enc = new byte[encryptor.OutputBlockSize];
                        if (d.Length != encryptor.InputBlockSize)
                        {
                            var final = encryptor.TransformFinalBlock(d, 0, d.Length);
                            if (final.Length > 0)
                            {
                                obs.OnNext(final);
                            }
                            hasFinished = true;
                        }
                        else
                        {
                            var read = encryptor.TransformBlock(d, 0, d.Length, enc, 0);
                            if (read == enc.Length)
                            {
                                obs.OnNext(enc);
                            }
                            else
                            {
                                var newEnc = new byte[read];
                                Buffer.BlockCopy(enc, 0, newEnc, 0, read);
                                obs.OnNext(newEnc);
                            }
                        }
                    },
                    (e) => { obs.OnError(e); },
                    () => 
                    {
                        if (!hasFinished)
                        {
                            var d = encryptor.TransformFinalBlock(new byte[0], 0, 0);
                            if (d.Length > 0)
                            {
                                obs.OnNext(d);
                            }
                        }

                        obs.OnCompleted(); 
                    });
            });
        }

        private static IObservable<byte[]> BufferBytes(IObservable<byte[]> stream, int bytesPerPacket)
        {
            return Observable.Create<byte[]>(obs =>
            {
                var buffer = new byte[bytesPerPacket];
                int position = 0;

                return stream.Subscribe((b) =>
                {
                    var count = b.Length;
                    var offset = 0;

                    while (count > 0)
                    {
                        var dataToRead = buffer.Length - position;
                        if (dataToRead > count)
                        {
                            dataToRead = count;
                        }

                        Buffer.BlockCopy(b, offset, buffer, position, dataToRead);

                        count -= dataToRead;
                        offset += dataToRead;
                        position += dataToRead;

                        if (position >= buffer.Length)
                        {
                            obs.OnNext(buffer);
                            buffer = new byte[bytesPerPacket];
                            position = 0;
                        }
                    }
                },
                (e) => { obs.OnError(e); },
                () =>
                {
                    if(position > 0)
                    {
                        // buffer will never be completely full at this point
                        // always have to copy it over!
                        var lastBytes = new byte[position];
                        Buffer.BlockCopy(buffer, 0, lastBytes, 0, position);
                        obs.OnNext(lastBytes);
                    }
                    obs.OnCompleted();
                });
            });
        }

        /// <summary>
        /// Decrypt an encryted stream of data
        /// </summary>
        /// <param name="data">
        /// Observable stream of data to decrypt (expected format is 4 bytes which 
        /// corresponds to the IV length, the IV iteself, and then the data to decrypt)
        /// </param>
        /// <returns>Observable stream of decrypted data</returns>
        public IObservable<byte[]> Decrypt(IObservable<byte[]> data)
        {
            return Observable.Create<byte[]>(obs =>
            {
                var aesProvider = new RijndaelManaged();
                aesProvider.Key = _key;
                ICryptoTransform decryptor = null;
                int position = 0;
                int streamPosition = 0;
                int ivLength = 0;

                byte[] initialBytes = new byte[4];

                return data.Subscribe((buffer) =>
                {
                    // Calculate length of IV
                    var count = buffer.Length;
                    var offset = 0;
                    var intBytesLength = 4 - position;
                    if (intBytesLength > 0)
                    {
                        if (intBytesLength > count) { intBytesLength = count; }
                        Buffer.BlockCopy(buffer, offset, initialBytes, position, intBytesLength);
                        offset = offset + intBytesLength;
                        count = count - intBytesLength;
                        position = position + intBytesLength;

                        if (position == 4)
                        {
                            ivLength = BitConverter.ToInt32(initialBytes, 0);
                            initialBytes = new byte[ivLength];
                        }
                    }

                    // Get the IV
                    var ivBytesLength = 4 + ivLength - position;
                    if (count > 0 && ivBytesLength > 0)
                    {
                        if (ivBytesLength > count) { ivBytesLength = count; }
                        Buffer.BlockCopy(buffer, offset, initialBytes, position - 4, ivBytesLength);
                        offset = offset + ivBytesLength;
                        count = count - ivBytesLength;
                        position = position + ivBytesLength;

                        // We finally have the IV, change the data stream to match
                        if (position == 4 + ivLength)
                        {
                            aesProvider.IV = initialBytes;
                            decryptor = aesProvider.CreateDecryptor();
                            initialBytes = new byte[decryptor.InputBlockSize];
                            streamPosition = 0;
                        }
                    }

                    // Do the decryption now
                    while (count > 0)
                    {
                        if (decryptor == null)
                        {
                            obs.OnError(new InvalidOperationException("Format incorrect, could not setup the crypto stream as IV data was missing"));
                            return;
                        }

                        var dataToRead = buffer.Length - offset;
                        if (dataToRead > count)
                        {
                            dataToRead = count;
                        }
                        if(dataToRead > initialBytes.Length - streamPosition)
                        {
                            dataToRead = initialBytes.Length - streamPosition;
                        }

                        Buffer.BlockCopy(buffer, offset, initialBytes, streamPosition, dataToRead);

                        count -= dataToRead;
                        offset += dataToRead;
                        streamPosition += dataToRead;

                        if (streamPosition >= initialBytes.Length)
                        {
                            var enc = new byte[decryptor.OutputBlockSize];
                            var read = decryptor.TransformBlock(initialBytes, 0, initialBytes.Length, enc, 0);
                            if (read == enc.Length)
                            {
                                obs.OnNext(enc);
                            }
                            else
                            {
                                var newEnc = new byte[read];
                                Buffer.BlockCopy(enc, 0, newEnc, 0, read);
                                obs.OnNext(newEnc);
                            }


                            initialBytes = new byte[decryptor.InputBlockSize];
                            streamPosition = 0;
                        }
                    }
                },
                (e) => { obs.OnError(e); },
                () => 
                {
                    try
                    {
                        var d = decryptor.TransformFinalBlock(initialBytes, 0, streamPosition);
                        if (d.Length > 0)
                        {
                            obs.OnNext(d);
                        }

                        obs.OnCompleted();
                    }
                    catch(Exception e)
                    {
                        obs.OnError(e);
                    }
                });
            });
        }
    }
}
