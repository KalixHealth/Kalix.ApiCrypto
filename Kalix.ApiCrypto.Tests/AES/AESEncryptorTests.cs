using Kalix.ApiCrypto.AES;
using NUnit.Framework;
using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace Kalix.ApiCrypto.Tests.AES
{
    [TestFixture]
    public class AESEncryptorTests
    {
        [Test]
        public void EcyrptDecryptUsingReadStreamsSucessful()
        {
            var encryptor = CreateEncryptor(128);
            var data = Encoding.UTF8.GetBytes("Test message of awesome");

            var encypted = encryptor.Encrypt(new MemoryStream(data));
            var decrypted = ReadData(encryptor.Decrypt(encypted, true));

            Assert.AreEqual("Test message of awesome", Encoding.UTF8.GetString(decrypted));
        }

        [Test]
        public void EcyrptDecryptUsingWriteStreamsSucessful()
        {
            var encryptor = CreateEncryptor(128);
            var data = Encoding.UTF8.GetBytes("Test message of awesome");
            var encypted = new MemoryStream();

            using (var tempEncStream = encryptor.Encrypt(encypted, false))
            {
                tempEncStream.Write(data, 0, data.Length);
            }

            var decrypted = new MemoryStream();
            using (var tempDecStream = encryptor.Decrypt(decrypted))
            {
                var encData = encypted.ToArray();
                tempDecStream.Write(encData, 0, encData.Length);
            }

            Assert.AreEqual("Test message of awesome", Encoding.UTF8.GetString(decrypted.ToArray()));
        }

        [Test]
        public void AES256EncryptsAndDecrypts()
        {
            var encryptor = CreateEncryptor(256);
            var data = Encoding.UTF8.GetBytes("Test message of awesome");

            var encypted = encryptor.Encrypt(new MemoryStream(data));
            var decrypted = ReadData(encryptor.Decrypt(encypted, true));

            Assert.AreEqual("Test message of awesome", Encoding.UTF8.GetString(decrypted));
        }

        [Test]
        public void AES256EncryptNotTheSame()
        {
            var encryptor = CreateEncryptor(256);
            var data = Encoding.UTF8.GetBytes("Test message of awesome");

            var encypted = Convert.ToBase64String(ReadData(encryptor.Encrypt(new MemoryStream(data))));
            var encypted2 = Convert.ToBase64String(ReadData(encryptor.Encrypt(new MemoryStream(data))));

            Assert.AreNotEqual(encypted, encypted2);
        }

        [Test]
        public void AES128EncryptsAndDecrypts()
        {
            var encryptor = CreateEncryptor(128);
            var data = Encoding.UTF8.GetBytes("Test message of awesome");

            var encypted = encryptor.Encrypt(new MemoryStream(data));
            var decrypted = ReadData(encryptor.Decrypt(encypted, true));

            Assert.AreEqual("Test message of awesome", Encoding.UTF8.GetString(decrypted));
        }

        [Test]
        public void AES128EncryptNotTheSame()
        {
            var encryptor = CreateEncryptor(128);
            var data = Encoding.UTF8.GetBytes("Test message of awesome");

            var encypted = Convert.ToBase64String(ReadData(encryptor.Encrypt(new MemoryStream(data))));
            var encypted2 = Convert.ToBase64String(ReadData(encryptor.Encrypt(new MemoryStream(data))));

            Assert.AreNotEqual(encypted, encypted2);
        }

        [Test]
        public void AES192EncryptsAndDecrypts()
        {
            var encryptor = CreateEncryptor(192);
            var data = Encoding.UTF8.GetBytes("Test message of awesome");

            var encypted = encryptor.Encrypt(new MemoryStream(data));
            var decrypted = ReadData(encryptor.Decrypt(encypted, true));

            Assert.AreEqual("Test message of awesome", Encoding.UTF8.GetString(decrypted));
        }

        [Test]
        public void AES192EncryptNotTheSame()
        {
            var encryptor = CreateEncryptor(192);
            var data = Encoding.UTF8.GetBytes("Test message of awesome");

            var encypted = Convert.ToBase64String(ReadData(encryptor.Encrypt(new MemoryStream(data))));
            var encypted2 = Convert.ToBase64String(ReadData(encryptor.Encrypt(new MemoryStream(data))));

            Assert.AreNotEqual(encypted, encypted2);
        }

        [Test]
        [ExpectedException(typeof(CryptographicException))]
        public void InvalidAESKeyCausesError()
        {
            var encryptor = new AESEncryptor(new byte[] { 20, 19, 29, 28, 13 });
            var data = Encoding.UTF8.GetBytes("Test message of awesome");
            var encypted = Convert.ToBase64String(ReadData(encryptor.Encrypt(new MemoryStream(data))));
        }

        private AESEncryptor CreateEncryptor(int keySizeInt)
        {
            var aes = new RijndaelManaged();
            aes.KeySize = keySizeInt;
            aes.GenerateKey();

            return new AESEncryptor(aes.Key);
        }

        private byte[] ReadData(Stream stream)
        {
            using (var dataStream = new MemoryStream())
            {
                stream.CopyTo(dataStream);
                return dataStream.ToArray();
            }
        }
    }
}
