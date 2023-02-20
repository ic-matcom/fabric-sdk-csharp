using Org.BouncyCastle.Crypto;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using System.Runtime.ConstrainedExecution;
using Org.BouncyCastle.OpenSsl;

namespace FabricNetwork.Identities {
    /// <summary>
    /// An  <see cref="Identity"/> comprising an X.509 certificate and associated private key.
    /// </summary>
    public class X509Identity : Identity {
        private const string typeId = "X.509";
        private const string version = "1";

        /// Some hard coded labels for the identity cert.
        private const string jsonTypeId = "type";
        private const string jsonMspId = "mspId";
        private const string jsonVersion = "version";
        private const string jsonCredentials = "credentials";
        private const string jsonCertificate = "certificate";
        private const string jsonPrivateKey = "privateKey";


        private string Certificate;
        private AsymmetricKeyParameter PrivateKey;
        private string MSPId;

        /// <summary>
        /// Creates an X509Identity instance with the given certificate, private key and mspId.
        /// </summary>
        /// <param name="certificate">Certificate to instanciate the identity.</param>
        /// <param name="privateKey">Private key to instanciate the identity.</param>
        /// <param name="mspId">Organization msp identifier for this identity.</param>
        public X509Identity(string certificate, AsymmetricKeyParameter privateKey, string mspId) {
            Certificate = certificate;
            PrivateKey = privateKey;
            MSPId = mspId;
        }

        /// <summary>
        /// Gets the identity's certificate.
        /// </summary>
        /// <returns>A string representing the identity's certificate.</returns>
        public string GetCertificate() {
            return Certificate;
        }

        /// <summary>
        /// Gets the identity's mspId.
        /// </summary>
        /// <returns>A string representing the identity's mspId.</returns>
        public string GetMspId() {
            return MSPId;
        }

        /// <summary>
        /// Gets the identity's private key.
        /// </summary>
        /// <returns>A AsymmetricKeyParameter representing the identity's private key.</returns>
        public AsymmetricKeyParameter GetPrivateKey() {
            return PrivateKey;
        }

        /// <summary>
        /// Converts privateKey to pem format.
        /// </summary>
        /// <param name="pk">Private key to convert.</param>
        /// <returns>A pem format string with the given private key.</returns>
        /// <exception cref="Exception"></exception>
        public static string ToPemString(AsymmetricKeyParameter pk) {
            StringWriter stringWriter = new StringWriter();
            try {
                PemWriter pemWriter = new PemWriter(stringWriter);
                pemWriter.WriteObject(pk);
                pemWriter.Writer.Flush();
            }

            catch (IOException exc) {
                throw new Exception("Could not read cert info.", exc);
            }

            return stringWriter.ToString();
        }

        /// <summary>
        /// Turns current identity into JObject.
        /// </summary>
        /// <returns>A JObject representation of the identity data.</returns>
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

        /// <summary>
        /// Creates a new identity instance from the JObject provided.
        /// </summary>
        /// <returns>An X509Identity representation of the JObject provided.</returns>
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
                JObject credentials = jsonIdentity[jsonCredentials] as JObject;
                string cert = credentials[jsonCertificate].Value<string>();
                string pk = credentials[jsonPrivateKey].Value<string>();

                AsymmetricKeyParameter signingKey;
                using (var textReader = new StringReader(pk)) {
                    PemReader pemReader = new PemReader(textReader);
                    var privateKey = pemReader.ReadObject() as AsymmetricCipherKeyPair;
                    return new X509Identity(cert, privateKey.Private, mspId);
                }
            }
            catch (Exception exc) {
                throw new Exception($"Could not read identity data from json: {jsonIdentity}. Wrong format.");
            }
        }
    }
}