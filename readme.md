# Kalix.ApiCrypto

Useful collection of classes to help with security of api endpoints

Features:
- Create ECDSA (P521, P384, P256) key pairs (and export to pfx and cer)
- Create Json Web Tokens signed with ECDSA (P521, P384, P256) certificate
- Create Cng based RSA key pairs (and export to pfx and cer)
- Create secure AES keys using RSA certificates
- Encrypt/Decrypt files using AES with best practise in mind

## Examples of use

### Global encryption (RSA/AES hybrid)

Certificate based encryption is really useful for separation of a codebase to the maintenance
of a public/private key pair. It's downside is that the encryption is much slower due to the
much larger key sizes of asymmetric (ie RSA) vs symmetric (ie AES) algorithms.

This example will set up a hybrid approach. You will have a strong RSA certifate, which you
will use to encrypt an AES key blob. The blob can then be stored on azure blob storage or Amazon S3
as an example. When your server starts up it will use the RSA certificate to decrypt this blob.
Once decrypted the AES symmetric key can be used to encrypt/decrypt all your records.

First step is to create the RSA certificate and the encrypted AES shared key:

	// Creates an RSA key with key size of 4096 by default
    var cert = RSACertificateBuilder.CreateNewCertificate("SubjectName");

	// Export public/private keypair
    var privateData = cert.Export(X509ContentType.Pkcs12, "password");
    File.WriteAllBytes(Path.GetFullPath("private.pfx"), privateData);

	// Create a blob that can be saved in blob storage or S3 etc
	var blobData = AESBlob.CreateBlob(AESKeySize.AES256, cert);

You will have to install the public/private key pair on all servers that need to encrypt/decrypt
data. It will only be used to extract the AES key from the blob:

    // Get the certificate from the store
    var store = new X509Store(StoreName.My, StoreLocation.CurrentUser);
    store.Open(OpenFlags.ReadOnly);
    var cert = store.Certificates.Find(X509FindType.FindBySubjectName, "SubjectName", false)[0];

	// Create the encryptor
	var encryptor = AESBlob.CreateEncryptor(blobData, cert);

The encryptor has an `Encypt` and `Decrypt` method that is (read) stream based. This makes it
easy to use for small or large files. It also follows best practice by creating a new IV per 
file and adding it to the start of the stream. 

### Access Tokens (inc. OAuth)

Kalix is broken up into two parts. One server serves up the content and deals with
authentication and the other serves up sensitive patient data. Due to privacy requirements
the patient records might need to reside in the country of origin. This means our systems cannot
share a db etc without some serious latency.

In this scenario we can authenticate our users via a central authentication server. Once
authenticated we can generate short lived access tokens that the user can use to access
the alternative server that holds the patient records. The data is open but is signed using
the private ECDSA key. ECDSA is similar to DSA but the key length is smaller which allows
us to produce much smaller access tokens with the same level of security.

Since we are using Azure we will have the ECDSA key stored as a certificate. This allows us
to seperate the managing of the super secret private key and our codebase.

The first step is to create the certificates we will need on each server. 

    var cert = ECCertificateBuilder.CreateNewSigningCertificate("SubjectName");

	// Export public/private keypair
    var privateData = cert.Export(X509ContentType.Pkcs12, "password");
    File.WriteAllBytes(Path.GetFullPath("private.pfx"), privateData);

	// Export public key
    var publicData = cert.Export(X509ContentType.Cert);
    File.WriteAllBytes(Path.GetFullPath("public.cer"), publicData);

The pfx should be installed on the machine that will create the access tokens. The cer
should be installed on the machine that needs to verify them.

Now when you need to create an access token in your oauth flow you can use the JsonWebToken
class:

    // Get the certificate from the store
    var store = new X509Store(StoreName.My, StoreLocation.CurrentUser);
    store.Open(OpenFlags.ReadOnly);
    var cert = store.Certificates.Find(X509FindType.FindBySubjectName, "SubjectName", false)[0];

	// Create an access token that is signed (on authentication server)
	var data = new { sub = "custId", aud = "scope1,scope2", exp = 1300819380 };
	var token = JsonWebToken.EncodeUsingECDSA(data, cert);

	// On resource server we can verify and use this data
	dynamic tokenData = JsonWebToken.DecodeUsingECDSA<object>(token, cert);
	var customerId = (string)tokenData.sub;
	var exp = (int)tokenData.exp;

	// Make sure to test expiry date, but apart from that we know customerId
	// can be trusted and we can release information for that customer

Check out [Claims](http://self-issued.info/docs/draft-ietf-oauth-json-web-token.html#Claims) on the
JWT reference docs for claims you might use in your access token.