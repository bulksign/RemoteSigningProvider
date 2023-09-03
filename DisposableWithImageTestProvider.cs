using System.Reflection;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Bulksign.Extensibility;
using Bulksign.Extensibility.Parameters;

namespace Bulksign.Sample
{

	public class DisposableWithImageTestProvider : IDisposableSignProvider
	{

		private static string SIGNATURE_IMAGE = "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";


		private static SignerField[] fields =
		{
			new SignerField
			{
				Key   = "Expiration Date",
				Value = "",
				Type  = FieldType.Date,
			},
			new SignerField
			{
				Key   = "Full Name",
				Value = "",
				Type  = FieldType.Text,
			},
			new SignerField
			{
				Key   = "Age",
				Value = "",
				Type  = FieldType.Number,
			},
			new SignerField
			{
				Key   = "Document Number",
				Value = "",
				Type  = FieldType.Text,
			},
		};


		public Dictionary<string,string> Settings
		{
			get;
			set;
		}

		public string ProviderName => nameof(DisposableTestProvider);

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

		public event LogDelegate? Log;

		public OperationResult VerifySigner(SignerDetails signerInformation,Dictionary<string,string> options)
		{
			return new OperationResult
			{
				IsSuccess = true
			};
		}


		public DisposableOtpResult SendOtp(DisposableSendOtp otp,SignerDetails signerDetails,Dictionary<string,string> options)
		{
			Log(LogLevel.Info,null,$"Sending OTP to {signerDetails.PhoneNumber}");

			return new DisposableOtpResult
			{
				IsSuccess     = true,
				TransactionId = "438634"  //if the SMS gateway provides a unique transaction identifier, please return it here.
			};
		}

		public OperationResult ValidateOtp(DisposableValidateOtp otp,SignerDetails signerDetails,Dictionary<string,string> options)
		{
			return new OperationResult
			{
				IsSuccess = true
			};
		}

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

		public IssuanceAgreementResult GetIssuanceAgreement(SignerDetails signerDetails,Dictionary<string,string> options)
		{
			return new IssuanceAgreementResult
			{
				IsSuccess = true,
				Agreement = $"<h3>Certificate Issuer Agreement for {signerDetails.Name}</h3><br/>\r\n\r\nLorem ipsum dolor sit amet, consectetur adipiscing elit. Nullam hendrerit nulla eu justo maximus consequat. Proin sit amet enim sagittis, malesuada elit ut, mattis augue. Phasellus ultricies mollis ante id vestibulum. Nulla facilisi. Fusce in enim magna. Mauris laoreet sagittis semper. Fusce ac ligula vitae sem elementum porta. Cras volutpat eu erat in condimentum.\r\n\r\nNunc euismod augue vel mattis maximus. Etiam eleifend pellentesque turpis, eget ultricies ante posuere at. Nullam tristique id lorem sit amet ullamcorper. Integer volutpat dui enim, sed egestas lorem suscipit non. Curabitur aliquam turpis metus, nec cursus sapien suscipit id. Suspendisse maximus ligula a enim pretium suscipit. Aliquam erat volutpat. Phasellus odio odio, molestie sed eros sed, rhoncus volutpat augue. Aenean dictum, mauris porttitor semper malesuada, purus neque eleifend mi, vitae venenatis nisi lectus ut eros. Suspendisse ac diam at dolor lacinia molestie. Quisque augue quam, sollicitudin at neque vitae, dictum auctor felis. Pellentesque elementum dapibus turpis ultricies venenatis. Etiam eu magna ex. Duis molestie erat eleifend iaculis ultricies. Vestibulum vel arcu vel felis feugiat porttitor.\r\n\r\nPhasellus tincidunt porttitor turpis eget tristique. Sed lacinia magna ut orci maximus aliquam. In aliquam lorem sit amet elit auctor, et tincidunt sapien pellentesque. Aenean interdum tempor tellus in auctor. Ut lacinia elit ligula, ac sodales tortor commodo sit amet. Orci varius natoque penatibus et magnis dis parturient montes, nascetur ridiculus mus. Sed ultricies lectus a consectetur dictum. Donec accumsan et orci sed feugiat. Sed nec elit metus. Nulla facilisis arcu non odio viverra, scelerisque lacinia lacus molestie. Phasellus quis tortor tincidunt, pulvinar augue at, ultricies justo.\r\n\r\nFusce dignissim purus in tortor hendrerit fringilla. Nunc interdum nisi sed dui pulvinar ultrices. Nunc vel aliquet metus, at posuere diam. Duis feugiat elit sed orci bibendum, id ultrices nisl lobortis. Maecenas eget molestie leo, id vestibulum turpis. Proin sit amet leo metus. Donec massa tellus, egestas sed finibus eget, feugiat eget mauris. Duis elementum, nunc ut tempus cursus, libero magna consectetur nisi, quis laoreet ante tellus gravida sem. Pellentesque non tellus felis. Donec mollis ipsum nibh, vitae consectetur diam elementum id. Nullam posuere arcu sit amet nisl scelerisque, in bibendum nulla aliquam. Suspendisse ac pellentesque eros. In enim purus, tincidunt id fringilla a, facilisis non mauris. Quisque quis urna id massa egestas maximus vitae nec orci. Suspendisse finibus maximus lobortis.\r\n\r\nAenean aliquam tortor eu nunc interdum, elementum tempor eros vehicula. Vestibulum ante ipsum primis in faucibus orci luctus et ultrices posuere cubilia curae; Maecenas ac lacus egestas, lacinia nulla vitae, semper nibh. Suspendisse sollicitudin malesuada mi sit amet dignissim. Nullam quis maximus est. Quisque in velit egestas, tristique tellus quis, ultrices erat. Sed nisi dui, pellentesque quis dignissim nec, faucibus a metus. Aenean ac dignissim lacus, vitae efficitur libero. Nullam finibus pulvinar urna non pharetra. Sed vitae tincidunt erat. Nullam pharetra justo vitae ipsum aliquam, scelerisque commodo elit porttitor. Integer fermentum erat purus, vitae posuere turpis scelerisque sit amet. Vivamus massa urna, elementum et ornare et, rutrum in metus. Sed vitae leo malesuada, dapibus mi et, scelerisque felis. Sed nec sodales diam. ",
				Conditions = new[]
				{
					"I agree with certificate issuing"," I accept the General Terms and Conditions and the one-sided clauses set forth in SECTION B","I give the consent to the processing of personal data"
				},
				RequestIdentifier = Guid.NewGuid().ToString()
			};
		}

		public DisposableSignatureResult GetSignatureImage(SignerDetails signerDetails,int signatureHeight,int signatureWidth,Dictionary<string,string> options)
		{
			return new DisposableSignatureResult()
			{
				IsSuccess      = true,
				SignatureImage = Convert.FromBase64String(SIGNATURE_IMAGE)
			};
		}

		public SignerField[] Fields
		{
			get => fields;
			set
			{

			}
		}

		public bool ProvidesSignatureImage => true;

		public bool RequiresIssuerAgreementAcceptance => true;

		public bool IsPhoneNumberRequiredForSigner => true;

		public int OtpValiditySeconds => 300;

		public string OtpLocalizationKey
		{
			get;
			set;
		}

		public int SignatureIdentifier => 170;


		public string SignatureName => "DisposableImageTest";

		public string PublicKeyBase64 => "MIIC7DCCAdSgAwIBAgIQSNhf6uTf8bdG3VKG3Df3szANBgkqhkiG9w0BAQsFADAUMRIwEAYDVQQDEwlsb2NhbGhvc3QwHhcNMjIwMzAyMTkyMzQyWhcNMjcwMzAyMDAwMDAwWjAUMRIwEAYDVQQDEwlsb2NhbGhvc3QwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDY2gtdq2Tt+/kMFYodCKbvlRNa/Q3oFR2k73xpZ8SIA/eyJI2MYO8HKks+nwMN8+xyqaYCyR4hbBOXWWaF1OfU2Ch2hR6rhTJaY0JiPE9ssPHrm8AeXm3evV8fOTZGl2GW8yzR4PdJiKexL9o1Z/pMcgzkBNyye1M2uKhIE8ermEPxpgcFeAEN1ocmr7RSNiIM7eSiTkGZqP4dFu+COpy9OEdfcqEUA1aKlyQIeuqOv6ZGdem5SDdfjEbHSRF3CLKWr9u20J0pYBZeT47LoPF8GjsauCR1V2J5BPQ4HglOMcmy/A9avnaFWji1cobP3lcD9o3pyliKYQ+yhMngucdZAgMBAAGjOjA4MAsGA1UdDwQEAwIEsDATBgNVHSUEDDAKBggrBgEFBQcDATAUBgNVHREEDTALgglsb2NhbGhvc3QwDQYJKoZIhvcNAQELBQADggEBAJEEAEu1nyELacnlJbfiO6HKidEAe7WzUxLwMPJRcqWegU47G1WYV3maINoMJjnbbtTXEil6IhFBmIo/l2VDCQzP/NiYP4R+mEsOMh8LGRumpo3SqeaZBb+fJSqHAfomOuGzPsNmU68XtXnkh6HiI4qQamuVKF2D0sNWRXqz6e/0mDVSlHgYsJScA+BvypCSW9+RWdYTG0G7IHPEn6tu5DyNxHkAY17RBoB7DJuLb/Kd8e4k2gqwP2QL8SwFi9L+myS71ww6OradFlgjvtcA107tEzr7yAAu4XZPYEK2FGMpqiIL2H7yH7pYj4zpDAlrmac30pG2tfc8ry+tAJkepys=";

	}
}