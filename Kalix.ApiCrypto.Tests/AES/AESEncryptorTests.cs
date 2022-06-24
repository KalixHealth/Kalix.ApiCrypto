using Kalix.ApiCrypto.AES;
using NUnit.Framework;
using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace Kalix.ApiCrypto.Tests.AES;

[TestFixture]
public class AESEncryptorTests
{
    [Test]
    public void EcyrptDecryptUsingWriteStreamsSucessful()
    {
        var encryptor = CreateEncryptor(128);

        byte[] decrypted;
        using (var ms = new MemoryStream())
        {
            using (var en = encryptor.Decrypt(ms, false))
            using (var de = encryptor.Encrypt(en, false))
            using (var sr = new StreamWriter(de))
            {
                sr.Write("Test message of awesome");
            }

            decrypted = ms.ToArray();
        }

        Assert.AreEqual("Test message of awesome", Encoding.UTF8.GetString(decrypted));
    }

    [Test]
    public void EcyrptDecryptUsingReadStreamsSucessful()
    {
        var encryptor = CreateEncryptor(128);
        var data = Encoding.UTF8.GetBytes("Test message of awesome");

        string decrypted;
        using (var ms = new MemoryStream(data))
        using (var en = encryptor.Encrypt(ms, true))
        using (var de = encryptor.Decrypt(en, true))
        using (var sr = new StreamReader(de))
        {
            decrypted = sr.ReadToEnd();
        }

        Assert.AreEqual("Test message of awesome", decrypted);
    }

    [Test]
    public void AES256EncryptsAndDecrypts()
    {
        var encryptor = CreateEncryptor(256);
        var data = Encoding.UTF8.GetBytes("Test message of awesome");

        var encypted = encryptor.Encrypt(data);
        var decrypted = encryptor.Decrypt(encypted);

        Assert.AreEqual("Test message of awesome", Encoding.UTF8.GetString(decrypted));
    }

    [Test]
    public void AES256EncryptNotTheSame()
    {
        var encryptor = CreateEncryptor(256);
        var data = Encoding.UTF8.GetBytes("Test message of awesome");

        var encypted = Convert.ToBase64String(encryptor.Encrypt(data));
        var encypted2 = Convert.ToBase64String(encryptor.Encrypt(data));

        Assert.AreNotEqual(encypted, encypted2);
    }

    [Test]
    public void AES128EncryptsAndDecrypts()
    {
        var encryptor = CreateEncryptor(128);
        var data = Encoding.UTF8.GetBytes("Test message of awesome");

        var encypted = encryptor.Encrypt(data);
        var decrypted = encryptor.Decrypt(encypted);

        Assert.AreEqual("Test message of awesome", Encoding.UTF8.GetString(decrypted));
    }

    [Test]
    public void AES128EncryptNotTheSame()
    {
        var encryptor = CreateEncryptor(128);
        var data = Encoding.UTF8.GetBytes("Test message of awesome");

        var encypted = Convert.ToBase64String(encryptor.Encrypt(data));
        var encypted2 = Convert.ToBase64String(encryptor.Encrypt(data));

        Assert.AreNotEqual(encypted, encypted2);
    }

    [Test]
    public void AES192EncryptsAndDecrypts()
    {
        var encryptor = CreateEncryptor(192);
        var data = Encoding.UTF8.GetBytes("Test message of awesome");

        var encypted = encryptor.Encrypt(data);
        var decrypted = encryptor.Decrypt(encypted);

        Assert.AreEqual("Test message of awesome", Encoding.UTF8.GetString(decrypted));
    }

    [Test]
    public void AES192EncryptNotTheSame()
    {
        var encryptor = CreateEncryptor(192);
        var data = Encoding.UTF8.GetBytes("Test message of awesome");

        var encypted = Convert.ToBase64String(encryptor.Encrypt(data));
        var encypted2 = Convert.ToBase64String(encryptor.Encrypt(data));

        Assert.AreNotEqual(encypted, encypted2);
    }

    [Test]
    public void InvalidAESKeyCausesError()
    {
        Assert.Throws(typeof(CryptographicException), () =>
        {
            var encryptor = new AESEncryptor(new byte[] { 20, 19, 29, 28, 13 });
            var data = Encoding.UTF8.GetBytes("Test message of awesome");
            var encypted = Convert.ToBase64String(encryptor.Encrypt(data));
        });
    }

    [Test]
    public void EmptyDataEncryptDecryptIsSuccessful()
    {
        var encryptor = CreateEncryptor(256);
        var data = Array.Empty<byte>();

        var encypted = encryptor.Encrypt(data);
        var decrypted = encryptor.Decrypt(encypted);

        Assert.AreEqual(0, decrypted.Length);
    }

    private static AESEncryptor CreateEncryptor(int keySizeInt)
    {
        var aes = Aes.Create();
        aes.KeySize = keySizeInt;
        aes.GenerateKey();

        return new AESEncryptor(aes.Key);
    }
}