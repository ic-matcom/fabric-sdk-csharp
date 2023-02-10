using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.Sec;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509.Extension;
using System.Collections;
using X509Extension = Org.BouncyCastle.Asn1.X509.X509Extension;
using Org.BouncyCastle.Math;


namespace FabricCaClient.Crypto {
    public class CryptoPrimitives {
        private int _securityLevel = 256;
        private string _curveName = "secp256r1";
        private string _encryptionName = "EC";
        private string _signatureAlgorithm = "SHA256withECDSA";

        public IDictionary<int, string> SLevelToCurveMapping = new Dictionary<int, string>()
        {
            { 256, "secp256r1" },
            { 384, "secp384r1"}
        };


        public void SetExcryptionName(string eName) {
            _encryptionName = eName;
        }

        public void SetCurveName(int sLevel) {
            _securityLevel = sLevel;
            _curveName = SLevelToCurveMapping[sLevel];
        }

        public void SetSignatureAlgorithm(string sAlgorithm) {
            _signatureAlgorithm = sAlgorithm;
        }

        /// <summary>
        /// Generates an asymetric KeyPair.
        /// </summary>
        /// <returns></returns>
        /// <exception cref="CryptoException"></exception>
        internal AsymmetricCipherKeyPair GenerateKeyPair() {
            try {
                // get the object identifier given by curveName
                DerObjectIdentifier doi = SecNamedCurves.GetOid(_curveName);

                // create and initialize eliptic curve keyPair generator instance
                ECKeyPairGenerator ecGen = new ECKeyPairGenerator(_encryptionName);
                ecGen.Init(new ECKeyGenerationParameters(doi, new SecureRandom()));

                // generate keyPair
                AsymmetricCipherKeyPair ackp = ecGen.GenerateKeyPair();

                return ackp;
            }
            catch (Exception exc) {
                throw new CryptoException("Unable to generate key pair", exc);
            }
        }

        /// <summary>
        /// Generates a Certificate signing request according to the given keyPair and subject.
        /// </summary>
        /// <param name="keyPair"></param>
        /// <param name="enrollmentId"></param>
        /// <returns></returns>
        /// <exception cref="CryptoException"></exception>
        internal string GenerateCSR(AsymmetricCipherKeyPair keyPair, string enrollmentId) {

            try {
                if (keyPair.Public == null || keyPair.Private == null) {
                    throw new CryptoException("Public and private keys must be provided");
                }

                var extensions = new Dictionary<DerObjectIdentifier, X509Extension> {
                    { X509Extensions.SubjectKeyIdentifier, new X509Extension(false, new DerOctetString(new SubjectKeyIdentifierStructure(keyPair.Public))) }
                };
                DerSet exts = new DerSet(new AttributePkcs(PkcsObjectIdentifiers.Pkcs9AtExtensionRequest, new DerSet(new X509Extensions(extensions))));

                // create the CSR subject
                //Variant 1
                IDictionary subjAttributes = new Hashtable {
                    { X509Name.CN, enrollmentId }
                };
                var subject = new X509Name(new ArrayList(subjAttributes.Keys), subjAttributes);

                // get signature factory corresponding to signature algorithm
                // PkcsObjectIdentifiers.Sha256WithRsaEncryption.Id
                ISignatureFactory sf = new Asn1SignatureFactory(_signatureAlgorithm, keyPair.Private, new SecureRandom());
                Pkcs10CertificationRequest pkcs10CertRequest = new Pkcs10CertificationRequest(sf, subject, keyPair.Public, exts);

                //variant 2
                //var subjAttributes = new Dictionary<DerObjectIdentifier, string> { { X509Name.CN, enrollmentId } };
                //ISignatureFactory sf = new Asn1SignatureFactory(_signatureAlgorithm, keyPair.Private, new SecureRandom());
                //Pkcs10CertificationRequest pkcs10CertRequest = new Pkcs10CertificationRequest(sf, new X509Name(subjAttributes.Keys.ToList(), subjAttributes), keyPair.Public, exts);
                //variant 2 end

                //var csr = Convert.ToBase64String(pkcs10CertRequest.GetEncoded());
                //var csrPem = Regex.Replace(csr, ".{64}", "$0\n");
                //strBuilder.Clear();
                //strBuilder.AppendLine($"-----BEGIN CERTIFICATE REQUEST-----");
                //strBuilder.AppendLine(csrPem);
                //strBuilder.AppendLine($"-----END CERTIFICATE REQUEST-----");
                //Console.WriteLine(strBuilder.ToString());

                // saving in base 64 format (pem)
                using StringWriter pemCert = new StringWriter();
                PemWriter pemWriter = new PemWriter(pemCert);
                pemWriter.WriteObject(pkcs10CertRequest);
                pemCert.Flush();
                return pemCert.ToString();
            }
            catch (Exception exc) {
                throw new CryptoException($"Unable to generate csr. {exc.Message}", exc);
            }
        }

        /// <summary>
        /// Signs a given message using the provided Private Key.
        /// </summary>
        /// <param name="keyPair">KeyPair containing private key.</param>
        /// <param name="messageToSign">Message to sign.</param>
        /// <returns>A signed message using the signatureAlgorithm specified.</returns>
        /// <exception cref="ArgumentException"></exception>
        internal string Sign(AsymmetricCipherKeyPair keyPair, byte[] messageToSign) {
            if (keyPair == null)
                throw new ArgumentException("Unable to sign data, private key must be provided");
            if (messageToSign == null || messageToSign.Length == 0)
                throw new ArgumentException("Unable to sign empty message");

            // Get a signer instance passing signature algorithm name (SHA256withECDSA)
            ISigner signer = SignerUtilities.GetSigner(_signatureAlgorithm);

            // Initilize signer with signing mode and signature key
            signer.Init(true, keyPair.Private);

            // Specify the data we want to generate signature for
            signer.BlockUpdate(messageToSign, 0, messageToSign.Length);

            // Generate cryptographic signature for the given message.
            byte[] signature = signer.GenerateSignature();

            if (keyPair.Private is ECPrivateKeyParameters) {
                ECPrivateKeyParameters privateKey = (ECPrivateKeyParameters)keyPair.Private;
                BigInteger curveN = privateKey.Parameters.N;
                BigInteger[] sigs = DecodeECDSASignature(signature);
                sigs = PreventMalleability(sigs, curveN);
                using (MemoryStream ms = new MemoryStream()) {
                    DerSequenceGenerator seq = new DerSequenceGenerator(ms);
                    seq.AddObject(new DerInteger(sigs[0]));
                    seq.AddObject(new DerInteger(sigs[1]));
                    seq.Close();
                    ms.Flush();
                    signature = ms.ToArray();
                }
            }

            return Convert.ToBase64String(signature);
        }

        private BigInteger[] PreventMalleability(BigInteger[] sigs, BigInteger curveN) {
            BigInteger cmpVal = curveN.Divide(BigInteger.Two);

            BigInteger sval = sigs[1];

            if (sval.CompareTo(cmpVal) > 0)
                sigs[1] = curveN.Subtract(sval);

            return sigs;
        }

        /// <summary>
        /// Decodes an ECDSA signature and returns a two element BigInteger array.
        /// </summary>
        /// <param name="signature">Bytes representing an ECDSA signature.</param>
        /// <returns>BigInteger array with signature's r and s values.</returns>
        /// <exception cref="CryptoException"></exception>
        private static BigInteger[] DecodeECDSASignature(byte[] signature) {
            Asn1InputStream asnInputStream = new Asn1InputStream(signature);
            Asn1Object asn1 = asnInputStream.ReadObject();
            BigInteger[] sigs = new BigInteger[2];
            int count = 0;
            if (asn1 is Asn1Sequence) {
                Asn1Sequence asn1Sequence = (Asn1Sequence)asn1;
                foreach (Asn1Encodable asn1Encodable in asn1Sequence) {
                    Asn1Object asn1Primitive = asn1Encodable.ToAsn1Object();
                    if (asn1Primitive is DerInteger) {
                        DerInteger asn1Integer = (DerInteger)asn1Primitive;
                        BigInteger integer = asn1Integer.Value;
                        if (count < 2)
                            sigs[count] = integer;
                        count++;
                    }
                }
            }

            if (count != 2)
                throw new CryptoException($"Invalid ECDSA signature. Expected count of 2 but got: {count}. Signature is: {BitConverter.ToString(signature).Replace("-", string.Empty)}");
            
            return sigs;
        }
    }
}