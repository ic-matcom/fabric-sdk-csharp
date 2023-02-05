using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.CryptoPro;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.Sec;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Encodings;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;
using Org.BouncyCastle.X509.Extension;
using System.Collections;
using System.Runtime.ConstrainedExecution;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.RegularExpressions;
using X509Extension = Org.BouncyCastle.Asn1.X509.X509Extension;

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
                IDictionary subjAttributes = new Hashtable {
                    { X509Name.CN, enrollmentId }
                };
                var subject = new X509Name(new ArrayList(subjAttributes.Keys), subjAttributes);

                // get signature factory corresponding to signature algorithm
                // PkcsObjectIdentifiers.Sha256WithRsaEncryption.Id
                ISignatureFactory sf = new Asn1SignatureFactory(_signatureAlgorithm, keyPair.Private, new SecureRandom());
                Pkcs10CertificationRequest pkcs10CertRequest = new Pkcs10CertificationRequest(sf, subject, keyPair.Public, exts);

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
    }
}