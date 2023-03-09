using System.Reflection;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Bulksign.Extensibility;
using Bulksign.Extensibility.Parameters;

namespace Bulksign.Sample
{

	public class DisposableTestProvider : IDisposableSignProvider
	{

		private static SignerField[] fields =
		{
			new SignerField
			{
				Key  = "Document Type",
				Type = FieldType.Options,
				Options = new Dictionary<string,List<FieldOption>>
				{
					{
						"*",new List<FieldOption>
						{
							new FieldOption
							{
								Key   = "ID",
								Value = "Identity Card"
							},
							new FieldOption
							{
								Key   = "P",
								Value = "Passport"
							},
							new FieldOption
							{
								Key   = "D",
								Value = "Driver License"
							}
						}
					}
				}
			},
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
			new SignerField
			{
				Key   = "Local Citizenship",
				Value = "",
				Type  = FieldType.Boolean,
			}
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
				TransactionId = "438634"
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
			throw new NotImplementedException();
		}

		public SignerField[] Fields
		{
			get => fields;
			set
			{

			}
		}

		public bool ProvidesSignatureImage => false;


		public bool RequiresIssuerAgreementAcceptance => true;

		public bool IsPhoneNumberRequiredForSigner => true;

		public int OtpValiditySeconds => 300;

		public string OtpLocalizationKey
		{
			get;
			set;
		}

		public int SignatureIdentifier => 169;


		public string SignatureName => "DisposableTest";

		public string PublicKeyBase64 => "MIIC7DCCAdSgAwIBAgIQSNhf6uTf8bdG3VKG3Df3szANBgkqhkiG9w0BAQsFADAUMRIwEAYDVQQDEwlsb2NhbGhvc3QwHhcNMjIwMzAyMTkyMzQyWhcNMjcwMzAyMDAwMDAwWjAUMRIwEAYDVQQDEwlsb2NhbGhvc3QwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDY2gtdq2Tt+/kMFYodCKbvlRNa/Q3oFR2k73xpZ8SIA/eyJI2MYO8HKks+nwMN8+xyqaYCyR4hbBOXWWaF1OfU2Ch2hR6rhTJaY0JiPE9ssPHrm8AeXm3evV8fOTZGl2GW8yzR4PdJiKexL9o1Z/pMcgzkBNyye1M2uKhIE8ermEPxpgcFeAEN1ocmr7RSNiIM7eSiTkGZqP4dFu+COpy9OEdfcqEUA1aKlyQIeuqOv6ZGdem5SDdfjEbHSRF3CLKWr9u20J0pYBZeT47LoPF8GjsauCR1V2J5BPQ4HglOMcmy/A9avnaFWji1cobP3lcD9o3pyliKYQ+yhMngucdZAgMBAAGjOjA4MAsGA1UdDwQEAwIEsDATBgNVHSUEDDAKBggrBgEFBQcDATAUBgNVHREEDTALgglsb2NhbGhvc3QwDQYJKoZIhvcNAQELBQADggEBAJEEAEu1nyELacnlJbfiO6HKidEAe7WzUxLwMPJRcqWegU47G1WYV3maINoMJjnbbtTXEil6IhFBmIo/l2VDCQzP/NiYP4R+mEsOMh8LGRumpo3SqeaZBb+fJSqHAfomOuGzPsNmU68XtXnkh6HiI4qQamuVKF2D0sNWRXqz6e/0mDVSlHgYsJScA+BvypCSW9+RWdYTG0G7IHPEn6tu5DyNxHkAY17RBoB7DJuLb/Kd8e4k2gqwP2QL8SwFi9L+myS71ww6OradFlgjvtcA107tEzr7yAAu4XZPYEK2FGMpqiIL2H7yH7pYj4zpDAlrmac30pG2tfc8ry+tAJkepys=";

	}
}