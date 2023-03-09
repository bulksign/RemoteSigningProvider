using System.Collections.Generic;
using System.IO;
using System.Net.Http;
using System.Reflection;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Bulksign.Extensibility;

namespace Bulksign.Sample
{
	public class RemoteSampleProvider : IRemoteSignProvider
	{
		public Dictionary<string,string> Settings
		{
			get;
			set;
		}

		public string ProviderName => "DemoSignatureProvider";

		public HttpClient HttpClient
		{
			get;
			set;
		}

		public IJsonSerializer JsonSerializer
		{
			get;
			set;
		}

		public event LogDelegate Log;

		public SignedHashResult SignHash(byte[] hash,SignerDetails signerInformation,Dictionary<string,string> options)
		{
			X509Certificate2 x = new X509Certificate2();

			string assemblyFolder = Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location);
			string certificatePath = Path.Combine(assemblyFolder,"test.pfx");

			//signing will be done in the sample with this self signed certificate.
			// When implementing the provider, you should load the certificate from the certificate store or contact the HSM to perform the signing.
			X509Certificate2 certificate = new X509Certificate2(File.ReadAllBytes(certificatePath),"test",X509KeyStorageFlags.Exportable);
			RSA key = certificate.GetRSAPrivateKey();
			byte[] signDataByHash = key.SignHash(hash,HashAlgorithmName.SHA256,RSASignaturePadding.Pkcs1);

			return new SignedHashResult
			{
				IsSuccess  = true,
				SignedHash = signDataByHash
			};
		}

		public bool UseableForAutomaticSigning => true;

		public int    SignatureIdentifier => 199;

		public string SignatureName       => "DemoSignature";

		//public key, in base64 format, of the certificate which will be used for signing. Certificate must support SHA256 hashing algorithm
		public string PublicKeyBase64 => "MIIC7DCCAdSgAwIBAgIQSNhf6uTf8bdG3VKG3Df3szANBgkqhkiG9w0BAQsFADAUMRIwEAYDVQQDEwlsb2NhbGhvc3QwHhcNMjIwMzAyMTkyMzQyWhcNMjcwMzAyMDAwMDAwWjAUMRIwEAYDVQQDEwlsb2NhbGhvc3QwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDY2gtdq2Tt+/kMFYodCKbvlRNa/Q3oFR2k73xpZ8SIA/eyJI2MYO8HKks+nwMN8+xyqaYCyR4hbBOXWWaF1OfU2Ch2hR6rhTJaY0JiPE9ssPHrm8AeXm3evV8fOTZGl2GW8yzR4PdJiKexL9o1Z/pMcgzkBNyye1M2uKhIE8ermEPxpgcFeAEN1ocmr7RSNiIM7eSiTkGZqP4dFu+COpy9OEdfcqEUA1aKlyQIeuqOv6ZGdem5SDdfjEbHSRF3CLKWr9u20J0pYBZeT47LoPF8GjsauCR1V2J5BPQ4HglOMcmy/A9avnaFWji1cobP3lcD9o3pyliKYQ+yhMngucdZAgMBAAGjOjA4MAsGA1UdDwQEAwIEsDATBgNVHSUEDDAKBggrBgEFBQcDATAUBgNVHREEDTALgglsb2NhbGhvc3QwDQYJKoZIhvcNAQELBQADggEBAJEEAEu1nyELacnlJbfiO6HKidEAe7WzUxLwMPJRcqWegU47G1WYV3maINoMJjnbbtTXEil6IhFBmIo/l2VDCQzP/NiYP4R+mEsOMh8LGRumpo3SqeaZBb+fJSqHAfomOuGzPsNmU68XtXnkh6HiI4qQamuVKF2D0sNWRXqz6e/0mDVSlHgYsJScA+BvypCSW9+RWdYTG0G7IHPEn6tu5DyNxHkAY17RBoB7DJuLb/Kd8e4k2gqwP2QL8SwFi9L+myS71ww6OradFlgjvtcA107tEzr7yAAu4XZPYEK2FGMpqiIL2H7yH7pYj4zpDAlrmac30pG2tfc8ry+tAJkepys=";
	}
}