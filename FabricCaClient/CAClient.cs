using Newtonsoft.Json.Linq;
using Newtonsoft.Json;
using System.Net.Http.Headers;
using System.Text;
using FabricCaClient.Crypto;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
using System.Text.RegularExpressions;
using FabricCaClient.Exceptions;
using System.Text.Json.Nodes;
using System.Net.Sockets;
using System.Runtime.ConstrainedExecution;

namespace FabricCaClient {
    /// <summary>
    /// A class that encapsulates a set of methods to communicate with Hyperledger Fabric (HF)'s Certificate Authority (CA).
    /// </summary>
    public class CAClient {
        // The available paths and operations for the API as described in https://github.com/hyperledger/fabric-ca/blob/main/swagger/swagger-fabric-ca.json.
        private static string defaultCaEndpoint = "http://localhost:7054";
        private static string defaultCaBaseUrl = "/api/v1/";

        private static readonly string caUrlEnroll = "enroll";
        private static readonly string caUrlRegister = "register";
        private static readonly string caUrlReenroll = "reenroll";
        private static readonly string caUrlRevoke = "revoke";
        private static readonly string caUrlInfo = "cainfo";
        private static readonly string caUrlGenCrl = "gencrl";
        private static readonly string caUrlCertificates = "certificates";
        private static readonly string caUrlIdemixCred = "idemix/credential";

        private string caName;
        private CryptoPrimitives cryptoPrimitives;
        private string caCertsPath;

        // HttpClient lifecycle management best practices:
        // https://learn.microsoft.com/dotnet/fundamentals/networking/http/httpclient-guidelines#recommended-use
        // returns error with ssl
        private static HttpClient sharedClient;

        /// <summary>
        /// Constructor for CAClient class.
        /// </summary>
        /// <param name="cryptoPrimitives">An instance of a Crypto Suite for PKI key creation/signing/verification.</param>
        /// <param name="caEndpoint">Http URL for the Fabric's certificate authority services endpoint.</param>
        /// <param name="baseUrl">Ca url where the base api resides. (Default "/api/v1/").</param>
        /// <param name="caCertsPath">Local ca certs path (for trusted root certs).</param>
        /// <param name="caName">Name of the CA to direct traffic to within server as FabricCa servers support multiple Certificate Authorities from a single server.</param>
        internal CAClient(CryptoPrimitives cryptoPrim, string caEndpoint = "", string baseUrl = "", string _caCertsPath = "", string _caName = "") {
            if (cryptoPrim == null)
                throw new ArgumentException("Crypto primitives not set. Please provide an instance of an ICryptoSuite implementation.");
            cryptoPrimitives = cryptoPrim;

            if (caEndpoint != "")
                defaultCaEndpoint = caEndpoint;
            if (baseUrl != "")
                defaultCaBaseUrl = caEndpoint;

            caCertsPath = _caCertsPath;
            caName = _caName;

            //var handler = new SocketsHttpHandler {
            //    PooledConnectionLifetime = TimeSpan.FromMinutes(15) // Recreate every 15 minutes
            //};

            //HttpClientHandler already uses SocketsHttpHandler under the hood
            var handler = new HttpClientHandler();
            if (caCertsPath != "") {
                var rootCertificate = new X509Certificate2(caCertsPath);
                var rootCertificates = new X509Certificate2Collection(rootCertificate);
                handler.ServerCertificateCustomValidationCallback = CreateCustomRootValidator(rootCertificates);
            }

            sharedClient = new HttpClient(handler) {
                BaseAddress = new Uri(defaultCaEndpoint + defaultCaBaseUrl),
            };
        }

        /// <summary>
        /// Returns CaName.
        /// </summary>
        /// <returns>A string containing caName.</returns>
        internal string GetCaName() {
            return caName;
        }

        /// <summary>
        /// Returns CryptoSuite instance in use.
        /// </summary>
        /// <returns>A CryptoPrimitives instance.</returns>
        internal CryptoPrimitives GetCryptoSuite() {
            return cryptoPrimitives;
        }

        /// <summary>
        /// Asks for ca basic info.
        /// </summary>
        /// <returns></returns>
        internal async Task<Tuple<string, string, string, string, string>> GetCaInfo() {
            try {
                // get the result field which is Base64-encoded PEM
                // check verify flag
                var jsonResponse = await GetAsync(caUrlInfo);

                JObject jsonst = JObject.Parse(jsonResponse);
                //bool success = jsonst["success"]?.Value<bool>() ?? false;// this is already being checked as EnsureSuccessStatusCode method keep being called.

                JObject result = jsonst["result"] as JObject;

                if (result == null)
                    throw new Exception("Error in HTTP call, result not found.");

                string caName = result["CAName"]?.Value<string>();
                string caChain = result["CAChain"]?.Value<string>();
                string issuerPK = result["IssuerPublicKey"]?.Value<string>();
                string issuerRevPK = result["IssuerRevocationPublicKey"]?.Value<string>();
                string version = result["Version"]?.Value<string>();

                return new Tuple<string, string, string, string, string>(caName, caChain, issuerPK, issuerRevPK, version);
            }
            catch (Exception exc) {
                throw (new EnrollmentException("Error in enrollment request.", exc));
            }
        }

        /// <summary>
        /// Enrolls a registered user in order to receive a signed X509 certificate.
        /// </summary>
        /// <param name="enrollmentId">Unique ID to use for enrollment, previusly registered with register call to the ca.</param>
        /// <param name="enrollmentSecret">The secret associated with the enrollment ID.</param>
        /// <param name="csr">A PEM-encoded string containing the CSR (Certificate Signing Request) based on PKCS #10. (Generated for the ca Service if not initially provided).</param>
        /// <param name="profile">The name of the signing profile to use when issuing the certificate.'tls' for a TLS certificate; otherwise, an enrollment certificate is issued.</param>
        /// <param name="attrRqs">A dictionary with attribute requests to be placed into the enrollment certificate. <remarks>Expected format is: "string attrName -> bool optional (wether or not the attr is required)".</remarks></param>
        /// <returns>A tuple containing a signed pem certificate and a string with caChain</returns>
        /// <exception cref="ArgumentException"></exception>
        /// <exception cref="Exception"></exception>
        public async Task<Tuple<string, string>> Enroll(string enrollmentId, string enrollmentSecret, string csr, string profile = "", Dictionary<string, bool> attrRqs = null) {
            if (enrollmentId == "" || enrollmentSecret == "" || csr == "")
                throw new ArgumentException($"Missing required parameters: enrollmentId-{enrollmentId}, enrollmentSecret-{enrollmentSecret} and csr-{csr} are all required.");

            JObject jsonBody = new JObject {
                new JProperty("certificate_request", csr)
            };
            if (caName != "")
                jsonBody.Add(new JProperty("caname", caName));
            if (profile != "")
                jsonBody.Add(new JProperty("profile", profile));
            if (attrRqs != null) {
                // converting attrRqs to JArray of JObjects
                JArray attrsArray = new JArray();
                foreach (string attrName in attrRqs.Keys) {
                    JObject attrObj = new JObject {
                        new JProperty("name", attrName),
                        new JProperty("optional", attrRqs[attrName])
                    };
                    attrsArray.Add(attrObj);
                }
                jsonBody.Add(new JProperty("attr_reqs", attrsArray));
            }

            try {
                // get the result field which is Base64-encoded PEM
                // check verify flag
                var jsonResponse = await PostAsync(caUrlEnroll, jsonBody.ToString(Formatting.None), enrollmentId, enrollmentSecret);

                JObject jsonst = JObject.Parse(jsonResponse);
                //bool success = jsonst["success"]?.Value<bool>() ?? false;// this is already being checked as EnsureSuccessStatusCode method keep being called.

                JObject result = jsonst["result"] as JObject;

                if (result == null)
                    throw new Exception("Error in HTTP call, result not found.");

                string signedPem = Encoding.UTF8.GetString(Convert.FromBase64String(result["Cert"]?.Value<string>() ?? ""));
                string caChain = Encoding.UTF8.GetString(Convert.FromBase64String(result["ServerInfo"]["CAChain"]?.Value<string>() ?? ""));

                return new Tuple<string, string>(signedPem, caChain);
            }
            catch (Exception exc) {
                throw (new EnrollmentException("Error in enrollment request.", exc));
            }
        }

        /// <summary>
        /// Reenrolls an identity in cases where his existing enrollment certificate is about to expire, or it has been compromised.
        /// </summary>
        /// <param name="registrar">The identity of the user that holds the existing enrollment certificate.</param>
        /// <param name="csr">A PEM-encoded string containing the CSR (Certificate Signing Request) based on PKCS #10.</param>
        /// <param name="attrRqs">A dictionary with attribute requests to be placed into the enrollment certificate. <remarks>Expected format is: "string attrName -> bool optional (wether or not the attr is required)".</remarks></param>
        /// <returns>A tuple containing a signed pem certificate and a string with caChain</returns>
        /// <exception cref="Exception"></exception>
        internal async Task<Tuple<string, string>> Reenroll(Enrollment registrar, string csr, Dictionary<string, bool> attrRqs = null) {
            JObject jsonBody = new JObject {
                new JProperty("certificate_request", csr)
            };
            if (caName != "")
                jsonBody.Add(new JProperty("caname", caName));
            if (attrRqs != null) {
                // converting attrRqs to JArray of JObjects
                JArray attrsArray = new JArray();
                foreach (string attrName in attrRqs.Keys) {
                    JObject attrObj = new JObject {
                        new JProperty("name", attrName),
                        new JProperty("optional", attrRqs[attrName])
                    };
                    attrsArray.Add(attrObj);
                }
                jsonBody.Add(new JProperty("attr_reqs", attrsArray));
            }

            try {
                // check verify flag
                var jsonResponse = await PostAsync(caUrlReenroll, jsonBody.ToString(Formatting.None), registrar);

                JObject jsonst = JObject.Parse(jsonResponse);
                //bool success = jsonst["success"]?.Value<bool>() ?? false;

                JObject result = jsonst["result"] as JObject;

                if (result == null)
                    throw new Exception("Error in HTTP call, result not found.");

                string signedPem = Encoding.UTF8.GetString(Convert.FromBase64String(result["Cert"]?.Value<string>() ?? ""));
                string caChain = Encoding.UTF8.GetString(Convert.FromBase64String(result["ServerInfo"]["CAChain"]?.Value<string>() ?? ""));

                return new Tuple<string, string>(signedPem, caChain);
            }
            catch (Exception exc) {
                throw (new ReenrollmentException("Error in reenrollment request.", exc));
            }
        }

        /// <summary>
        /// Registers an identity.
        /// </summary>
        /// <param name="enrollmentId">The enrollment ID which uniquely identifies an identity.</param>
        /// <param name="enrollmentSecret">The enrollment secret. If not provided, a random secret is generated.</param>
        /// <param name="maxEnrollments">The maximum number of times the secret can be reused to enroll.</param>
        /// <param name="attrs">An array of attribute names and values to give to the registered identity. 
        /// <remarks>Expected format is for each item is: Tuple{string name, string value, bool ecert}, 
        /// indicating name an value of the attribute and wether or not it should be included in an enrollment certificate by default.</remarks> 
        /// </param>
        /// <param name="registrar">The registrar that performs the operation.</param>
        /// <param name="role">The type of the identity (e.g. *user*, *app*, *peer*, *orderer*, etc). Default role is client.</param>
        /// <param name="affiliatiton">The affiliation of the new identity. If no affliation is provided, the affiliation of the registrar is used.</param>
        /// <returns>A string representing the enrollment secret of the newly registered identity.</returns>
        /// <exception cref="Exception"></exception>
        internal async Task<string> Register(string enrollmentId, string enrollmentSecret, int maxEnrollments, Tuple<string, string, bool>[] attrs, Enrollment registrar, string role = "", string affiliatiton = "") {
            JObject jsonBody = new JObject {
                new JProperty("id", enrollmentId),
                new JProperty("affiliation", affiliatiton),
                new JProperty("max_enrollments", maxEnrollments),
            };

            if (caName != "")
                jsonBody.Add(new JProperty("caname", caName));
            if (role != "")
                jsonBody.Add(new JProperty("type", role));
            if (enrollmentSecret != "")
                jsonBody.Add(new JProperty("secret", enrollmentSecret));
            if (attrs != null) {
                // converting attrs to JArray of JObjects
                JArray attrsArray = new JArray();
                foreach (var attrTuple in attrs) {
                    JObject attrObj = new JObject {
                        new JProperty("name", attrTuple.Item1),
                        new JProperty("value", attrTuple.Item2),
                        new JProperty("ecert", attrTuple.Item3)
                    };
                    attrsArray.Add(attrObj);
                }
                jsonBody.Add(new JProperty("attrs", attrsArray));
            }

            try {
                // get the result field which is Base64-encoded PEM
                // check verify flag
                var jsonResponse = await PostAsync(caUrlRegister, jsonBody.ToString(Formatting.None), registrar);

                JObject jsonst = JObject.Parse(jsonResponse);
                //bool success = jsonst["success"]?.Value<bool>() ?? false;

                JObject result = jsonst["result"] as JObject;

                if (result == null)
                    throw new Exception("Error in HTTP call, result not found.");

                string secret = result["secret"]?.Value<string>();

                return secret;
            }
            catch (Exception exc) {
                throw (new RegisterException("Error in register request.", exc));
            }
        }

        /// <summary>
        /// Revokes an identity or a given certificate. When revoking an identity all the relates certificaters are revoked, and further enroll calls with its id will be denied.
        /// </summary>
        /// <param name="enrollmentId">Id of the identity to revoke</param>
        /// <param name="aki">Authority Key Identifier (hex encoded) for the certificate to revoke. 
        /// <remarks>
        /// Required when revoking a certitificate, otherwise shoud be set to "".
        /// </remarks>
        /// </param>
        /// <param name="serial"> Serial number (hex encoded) for the certificate to revoke.
        /// <remarks>
        /// Required when revoking a certitificate, otherwise shoud be set to "".
        /// </remarks></param>
        /// <param name="reason">A reason for the revocation. Please visit <see href="https://www.rfc-editor.org/rfc/rfc5280.html#section-5.3.1">RFC 6960</see> for a list of correct values according to HF CA specifications.</param>
        /// <param name="genCrl">A boolean to indicate whether or not to generate a Certificate Revocation List.</param>
        /// <param name="registrar">The instance of a Enrollment encapsulating the identity that perfoms the revocation.</param>
        /// <returns>A base64 encoded PEM-encoded CRL.</returns>
        /// <exception cref="Exception"></exception>
        internal async Task<string> Revoke(string enrollmentId, string aki, string serial, string reason, bool genCrl, Enrollment registrar) {
            JObject jsonBody = new JObject {
                new JProperty("id", enrollmentId),
                new JProperty("aki", aki),
                new JProperty("serial", serial),
                new JProperty("reason", reason),
                new JProperty("gencrl", genCrl),
            };

            if (caName != "")
                jsonBody.Add(new JProperty("caname", caName));

            try {
                // get the result field which is Base64-encoded PEM
                // check verify flag and caclient attr
                var jsonResponse = await PostAsync(caUrlRevoke, jsonBody.ToString(Formatting.None), registrar);

                JObject jsonst = JObject.Parse(jsonResponse);
                //bool success = jsonst["success"]?.Value<bool>() ?? false;

                JObject result = jsonst["result"] as JObject;

                if (result == null)
                    throw new Exception("Error in HTTP call, result not found.");

                //verify following converison
                string crl = result["CRL"]?.Value<string>();

                return crl;
            }
            catch (Exception exc) {
                throw (new RevokeException("Error in revoke request.", exc));
            }
        }

        /// <summary>
        /// Makes a get async call to the gicen url.
        /// </summary>
        /// <param name="url">url to direct the call.</param>
        /// <returns>A string resulted from the Http post call.</returns>
        private static async Task<string> GetAsync(string url) {
            try {
                HttpResponseMessage response = await sharedClient.GetAsync(url);

                response.EnsureSuccessStatusCode();

                var jsonResponse = await response.Content.ReadAsStringAsync();

                return jsonResponse;
            }
            catch (Exception exc) {
                throw new Exception($"Error in GetAsync call to {url}.", exc);
            }
        }

        /// <summary>
        /// Makes a post call to given url using raw id and password provided as Autthentication Header.
        /// </summary>
        /// <param name="url">Target url.</param>
        /// <param name="content">Content of the request (converted form json format).</param>
        /// <param name="idx">Id to used for authentication.</param>
        /// <param name="pass">Password to used for authentication.</param>
        /// <returns>A string resulted from the Http post call.</returns>
        private async Task<string> PostAsync(string url, string content, string idx = "", string pass = "") {
            HttpRequestMessage request = new HttpRequestMessage(HttpMethod.Post, url);

            request.Content = new StringContent(content, Encoding.UTF8);
            request.Content.Headers.ContentType = MediaTypeHeaderValue.Parse("application/json");

            if (idx != "" && pass != "")
                request.Headers.Authorization = new AuthenticationHeaderValue("Basic", Convert.ToBase64String(Encoding.UTF8.GetBytes(idx + ":" + pass)));

            try {
                HttpResponseMessage response = await sharedClient.SendAsync(request);
                response.EnsureSuccessStatusCode();

                //deserialize
                var jsonResponse = await response.Content.ReadAsStringAsync();

                return jsonResponse;
            }
            catch (Exception exc) {
                throw new Exception($"Error in PostAsync call to {url}.", exc);
            }
        }

        /// <summary>
        /// Makes a post call to given url. Uses a token generated from registar and content as Autthentication Header.
        /// </summary>
        /// <param name="url">Target url.</param>
        /// <param name="content">Content of the request (converted form json format).</param>
        /// <param name="registrar">Identity that performs the call.</param>
        /// <returns>A string resulted from the Http post call.</returns>
        private async Task<string> PostAsync(string url, string content, Enrollment registrar) {
            HttpRequestMessage request = new HttpRequestMessage(HttpMethod.Post, url);

            if (registrar != null)
                request.Headers.TryAddWithoutValidation("Authorization", GenerateAuthToken(registrar, content));
            if (!string.IsNullOrEmpty(content)) {
                request.Content = new StringContent(content, Encoding.UTF8);
                request.Content.Headers.ContentType = MediaTypeHeaderValue.Parse("application/json");
            }

            try {
                HttpResponseMessage response = await sharedClient.SendAsync(request);
                response.EnsureSuccessStatusCode();

                var jsonResponse = await response.Content.ReadAsStringAsync();

                return jsonResponse;
            }
            catch (Exception exc) {
                throw new Exception($"Error in PostAsync call to {url}.", exc);
            }
        }

        /// <summary>
        /// Generates authorization token required for accessing fabric-ca APIs.
        /// </summary>
        /// <param name="registrar">The identity of the registrar who is performing the request.</param>
        /// <param name="content">Request body to sign.</param>
        /// <returns>An enrollment token consisting of two base 64 encoded parts separated by a period: an enrollment certificate; a signature over the certificate and body of request.</returns>
        private string GenerateAuthToken(Enrollment registrar, string content) {
            // convert json string of content to a base 64 string
            string convContent = Convert.ToBase64String(Encoding.UTF8.GetBytes(content));

            // convert string of cert to a base 64 string
            string cert = Convert.ToBase64String(Encoding.UTF8.GetBytes(registrar.Cert));

            // create message to sign
            string message = convContent + "." + cert;

            // convert to bytes array
            byte[] messageInBytes = Encoding.UTF8.GetBytes(message);

            // sign message
            string authToken = cert + "." + cryptoPrimitives.Sign(registrar.KeyPair, messageInBytes);

            return authToken;
        }

        /// <summary>
        /// A delegate that invokes a custom RemoteCertificateValidationCallback to validate that ssl communications are stablished via the owners of the given roots and intermediate certs.
        /// </summary>
        /// <param name="trustedRoots">A collection of the trusted X509Certificate2s as roots.</param>
        /// <param name="intermediates">A collection of the trusted X509Certificate2s as intermediates.</param>
        /// <returns>A RemoteCertificateValidationCallback that takes into account the given certificates.</returns>
        public static Func<HttpRequestMessage, X509Certificate2, X509Chain, SslPolicyErrors, bool> CreateCustomRootValidator(X509Certificate2Collection trustedRoots, X509Certificate2Collection intermediates = null) {
            RemoteCertificateValidationCallback callback = CreateCustomRootRemoteValidator(trustedRoots, intermediates);
            return (message, serverCert, chain, errors) => callback(null, serverCert, chain, errors);
        }

        /// <summary>
        /// Creates a custom RemoteCertificateValidationCallback to validate that ssl communications are stablished via the owners of the given roots and intermediate certs.
        /// </summary>
        /// <param name="trustedRoots">A collection of the trusted X509Certificate2s as roots.</param>
        /// <param name="intermediates">A collection of the trusted X509Certificate2s as intermediates.</param>
        /// <returns></returns>
        /// <exception cref="ArgumentNullException"></exception>
        /// <exception cref="ArgumentException"></exception>
        public static RemoteCertificateValidationCallback CreateCustomRootRemoteValidator(X509Certificate2Collection trustedRoots, X509Certificate2Collection intermediates = null) {
            if (trustedRoots == null)
                throw new ArgumentNullException(nameof(trustedRoots));
            if (trustedRoots.Count == 0)
                throw new ArgumentException("No trusted roots provided", nameof(trustedRoots));

            X509Certificate2Collection roots = new X509Certificate2Collection(trustedRoots);
            X509Certificate2Collection intermeds = null;

            if (intermediates != null)
                intermeds = new X509Certificate2Collection(intermediates);

            intermediates = null;
            trustedRoots = null;

            return (sender, certificate, chain, errors) => {
                if ((errors & ~SslPolicyErrors.RemoteCertificateChainErrors) != 0)
                    return false;

                for (int i = 1; i < chain.ChainElements.Count; i++) {
                    chain.ChainPolicy.ExtraStore.Add(chain.ChainElements[i].Certificate);
                }

                if (intermeds != null)
                    chain.ChainPolicy.ExtraStore.AddRange(intermeds);

                chain.ChainPolicy.CustomTrustStore.Clear();
                chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
                chain.ChainPolicy.CustomTrustStore.AddRange(roots);
                
                return chain.Build((X509Certificate2)certificate);
            };
        }
    }
}
