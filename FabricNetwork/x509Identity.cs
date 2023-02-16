using Org.BouncyCastle.Crypto;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using System.Runtime.ConstrainedExecution;
using Org.BouncyCastle.OpenSsl;

namespace FabricNetwork {
    public class X509Identity : Identity {
        private const string typeId = "X.509";
        private const string version = "1";

        private const string jsonTypeId = "type";
        private const string jsonMspId = "mspId";
        private const string jsonVersion = "version";
        private const string jsonCredentials = "credentials";
        private const string jsonCertificate = "certificate";
        private const string jsonPrivateKey = "privateKey";


        private string Certificate;
        //private string PrivateKey;
        private AsymmetricCipherKeyPair PrivateKey;
        private string MSPId;

        public X509Identity(string certificate, AsymmetricCipherKeyPair privateKey, string mspId) {
            Certificate = certificate;
            PrivateKey = privateKey;
            MSPId = mspId;
        }

        public string GetCertificate() {
            return Certificate;
        }

        public string GetMspId() {
            return MSPId;
        }

        public AsymmetricCipherKeyPair GetPrivateKey() {
            return PrivateKey;
        }

        // consider moving to enrollment or a different utitilities file
        public static string ToPemString(AsymmetricCipherKeyPair certificate) {
            StringWriter stringWriter = new StringWriter();
            try {
                PemWriter pemWriter = new PemWriter(stringWriter);
                pemWriter.WriteObject(certificate);
                pemWriter.Writer.Flush();
            }

            catch (IOException exc) {
                throw new Exception("Could not read cert info.", exc);
            }

            return stringWriter.ToString();
        }

        public JObject ToJson() {
            JObject jsonIdentity = new JObject {
                new JProperty(jsonTypeId, typeId),
                new JProperty(jsonVersion, version),
                new JProperty(jsonMspId, MSPId),
                new JProperty(jsonCredentials, new JObject {
                    new JProperty(jsonCertificate, Certificate),
                    new JProperty(jsonPrivateKey, ToPemString(PrivateKey)),
                }),
            };

            return jsonIdentity;
        }

        public static X509Identity FromJson(JObject jsonIdentity) {
            try {
                string type = jsonIdentity[jsonTypeId].Value<string>();
                if (type != typeId) {
                    throw new Exception($"Invalid type identity type: {type}");
                }

                string idVersion = jsonIdentity[jsonVersion].Value<string>();
                if (idVersion != version) {
                    throw new Exception($"Unsupported identity version: {idVersion}");
                }

                string mspId = jsonIdentity[jsonMspId].Value<string>();
                JObject credentials = (jsonIdentity[jsonCredentials] as JObject);
                string cert = credentials[jsonCertificate].Value<string>();
                string pk = credentials[jsonPrivateKey].Value<string>();

                AsymmetricKeyParameter signingKey;
                using (var textReader = new StringReader(pk)) {
                    PemReader pemReader = new PemReader(textReader);
                    var keyPair = pemReader.ReadObject() as AsymmetricCipherKeyPair;
                    return new X509Identity(cert, keyPair, mspId);
                }
            }
            catch (Exception exc) {
                throw new Exception($"Could not read identity data from json: {jsonIdentity}. Wrong format.");
            }
        }
    }
}