using Newtonsoft.Json.Linq;
using Newtonsoft.Json;
using System.Net.Http.Headers;
using System.Text;
using FabricCaClient.Crypto;

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

        //borrar 
        string caVersion = "1.5.5";
        public string CAName { get; private set; }
        private bool? newPayloadType;

        /// <summary>
        /// Constructor for CAClient class
        /// </summary>
        /// <param name="cryptoPrim"></param>
        /// <param name="caEnpoint"></param>
        /// <param name="baseUrl"></param>
        /// <param name="_caCertsPath"></param>
        /// <param name="_caName"></param>
        public CAClient(CryptoPrimitives cryptoPrim, string caEnpoint = "", string baseUrl = "", string _caCertsPath = "", string _caName = "") {
            cryptoPrimitives = cryptoPrim;

            if (caEnpoint != "")
                defaultCaEndpoint = caEnpoint;
            if (baseUrl != "")
                defaultCaBaseUrl = caEnpoint;

            caCertsPath = _caCertsPath;
            caName = _caName;

            var handler = new SocketsHttpHandler {
                PooledConnectionLifetime = TimeSpan.FromMinutes(15) // Recreate every 15 minutes
            };
            sharedClient = new HttpClient(handler) {
                BaseAddress = new Uri(defaultCaEndpoint + defaultCaBaseUrl),
            };

            CAName = "ca-org1";
        }

        /// <summary>
        /// Asks for ca basic info
        /// </summary>
        /// <returns></returns>
        public async Task<string> GetCaInfo() {
            return await GetAsync(caUrlInfo);
        }

        /// <summary>
        /// Enrolls an identity.
        /// </summary>
        /// <param name="enrollmentId"></param>
        /// <param name="enrollmentSecret"></param>
        /// <param name="csr"></param>
        /// <param name="profile"></param>
        /// <param name="attrRqs"></param>
        /// <returns>A tuple containing a signed pem certificate and a string with caChain</returns>
        /// <exception cref="ArgumentException"></exception>
        /// <exception cref="Exception"></exception>
        public async Task<Tuple<string, string>> Enroll(string enrollmentId, string enrollmentSecret, string csr, string profile = "", string attrRqs = "") {
            if (enrollmentId == "" || enrollmentSecret == "" || csr == "")
                throw new ArgumentException($"Missing required parameters: enrollmentId-{enrollmentId}, enrollmentSecret-{enrollmentSecret} and csr-{csr} are all required");

            JObject jsonBody = new JObject {
                new JProperty("certificate_request", csr)
            };
            if (profile != "")
                jsonBody.Add(new JProperty("profile", profile));
            if (attrRqs != "")// attrRqs should already be a JArray of JObjects
                jsonBody.Add(new JProperty("attr_reqs", attrRqs));

            // get the result field which is Base64-encoded PEM
            // check verify flag
            var jsonResponse = await PostAsync(caUrlEnroll, jsonBody.ToString(Formatting.None), enrollmentId, enrollmentSecret);

            JObject jsonst = JObject.Parse(jsonResponse);
            bool success = jsonst["success"]?.Value<bool>() ?? false;
            if (success) {
                try {
                    JObject result = jsonst["result"] as JObject;
                    if (result != null) {
                        string signedPem = Encoding.UTF8.GetString(Convert.FromBase64String(result["Cert"]?.Value<string>() ?? ""));
                        string caChain = Encoding.UTF8.GetString(Convert.FromBase64String(result["ServerInfo"]["CAChain"]?.Value<string>() ?? ""));

                        return new Tuple<string, string>(signedPem, caChain);
                    }
                }
                catch (Exception exc) {
                    throw new Exception("Error in enrollment request", exc);
                }
            }
            throw (new Exception("Error in enrollment request"));
        }

        /// <summary>
        /// Reenrolls an identity.
        /// </summary>
        /// <param name="registrar"></param>
        /// <param name="csr"></param>
        /// <param name="attrRqs"></param>
        /// <returns></returns>
        /// <exception cref="Exception"></exception>
        public async Task<Tuple<string, string>> Reenroll(Enrollment registrar, string csr, string attrRqs = "") {
            JObject jsonBody = new JObject {
                new JProperty("certificate_request", csr)
            };
            if (attrRqs != "")// attrRqs should already be a JArray of JObjects
                jsonBody.Add(new JProperty("attr_reqs", attrRqs));

            // check verify flag
            var jsonResponse = await PostAsync(caUrlReenroll, jsonBody.ToString(Formatting.None), registrar);

            JObject jsonst = JObject.Parse(jsonResponse);
            bool success = jsonst["success"]?.Value<bool>() ?? false;

            if (success) {
                try {
                    JObject result = jsonst["result"] as JObject;
                    if (result != null) {
                        string signedPem = Encoding.UTF8.GetString(Convert.FromBase64String(result["Cert"]?.Value<string>() ?? ""));
                        string caChain = Encoding.UTF8.GetString(Convert.FromBase64String(result["ServerInfo"]["CAChain"]?.Value<string>() ?? ""));

                        return new Tuple<string, string>(signedPem, caChain);
                    }
                }
                catch (Exception exc) {
                    throw new Exception("Error in reenrollmente request", exc);
                }
            }
            throw (new Exception("Error in reenrollment request"));
        }

        /// <summary>
        /// Registers an identity.
        /// </summary>
        /// <param name="enrollmentId"></param>
        /// <param name="enrollmentSecret"></param>
        /// <param name="maxEnrollments"></param>
        /// <param name="attrs"></param>
        /// <param name="registrar"></param>
        /// <param name="role"></param>
        /// <param name="affiliatiton"></param>
        /// <returns></returns>
        /// <exception cref="Exception"></exception>
        public async Task<string> Register(string enrollmentId, string enrollmentSecret, int maxEnrollments, string attrs, Enrollment registrar, string role = "", string affiliatiton = "") {
            JObject jsonBody = new JObject {
                new JProperty("id", enrollmentId),
                new JProperty("affiliation", affiliatiton),
                new JProperty("max_enrollments", maxEnrollments),
            };

            if (role != "")
                jsonBody.Add(new JProperty("type", role));
            if (attrs != "")// attrs should already be a JArray of JObjects
                jsonBody.Add(new JProperty("attrs", attrs));
            if (enrollmentSecret != "")
                jsonBody.Add(new JProperty("secret", enrollmentSecret));

            // get the result field which is Base64-encoded PEM
            // check verify flag
            var jsonResponse = await PostAsync(caUrlRegister, jsonBody.ToString(Formatting.None), registrar);

            JObject jsonst = JObject.Parse(jsonResponse);
            bool success = jsonst["success"]?.Value<bool>() ?? false;
            if (success) {
                try {
                    JObject result = jsonst["result"] as JObject;
                    if (result != null) {
                        string secret = result["secret"]?.Value<string>();
                        return secret;
                    }
                }
                catch (Exception exc) {
                    throw new Exception("Error in register request", exc);
                }
            }
            throw (new Exception("Error in register request"));
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
        public async Task<string> Revoke(string enrollmentId, string aki, string serial, string reason, bool genCrl, Enrollment registrar) {
            JObject jsonBody = new JObject {
                new JProperty("id", enrollmentId),
                new JProperty("aki", aki),
                new JProperty("serial", serial),
                new JProperty("reason", reason),
                new JProperty("gencrl", genCrl),
            };

            // get the result field which is Base64-encoded PEM
            // check verify flag and caclient attr
            var jsonResponse = await PostAsync(caUrlRevoke, jsonBody.ToString(Formatting.None), registrar);

            JObject jsonst = JObject.Parse(jsonResponse);
            bool success = jsonst["success"]?.Value<bool>() ?? false;
            if (success) {
                try {
                    JObject result = jsonst["result"] as JObject;
                    if (result != null) {
                        //verify following converison
                        string crl = result["CRL"]?.Value<string>();
                        return crl;
                    }
                }
                catch (Exception exc) {
                    throw new Exception("Error in revoke request", exc);
                }
            }
            throw (new Exception("Error in revoke request"));
        }

        internal async Task<string[]> GetCertificates(Enrollment registrar) {
            var jsonResponse = await GetAsyncWithAuth(caUrlCertificates, "", registrar);

            JObject jsonst = JObject.Parse(jsonResponse);
            bool success = jsonst["success"]?.Value<bool>() ?? false;
            if (success) {
                try {
                    JObject result = jsonst["result"] as JObject;
                    if (result != null) {
                        JArray certs = result["certs"] as JArray;
                        if (certs != null && certs.Count > 0) {
                            string[] certificates = new string[certs.Count];
                            int i = 0;
                            foreach (JToken cert in certs) {
                                certs[i++] = cert["PEM"].Value<string>();
                            }
                            return certificates;
                        }
                    }
                }
                catch (Exception exc) {
                    throw new Exception("Error in revoke request", exc);
                }
            }
            throw (new Exception("Error in revoke request"));
        }

        static async Task<string> GetAsync(string url) {
            // as per the using keyword specification, this object is disposed correctly after going out of the scope definition
            using HttpResponseMessage response = await sharedClient.GetAsync(url);

            response.EnsureSuccessStatusCode();

            var jsonResponse = await response.Content.ReadAsStringAsync();
            return jsonResponse;
        }

        /// <summary>
        /// Makes a post call to given url using raw id and password provided as Autthentication Header.
        /// </summary>
        /// <param name="url">Target url.</param>
        /// <param name="content">Content of the request (converted form json format).</param>
        /// <param name="idx">Id to used for authentication.</param>
        /// <param name="pass">Password to used for authentication.</param>
        /// <returns>A string resulted from the Http post call.</returns>
        static async Task<string> PostAsync(string url, string content, string idx = "", string pass = "") {
            HttpRequestMessage request = new HttpRequestMessage(HttpMethod.Post, url);

            request.Content = new StringContent(content, Encoding.UTF8);
            request.Content.Headers.ContentType = MediaTypeHeaderValue.Parse("application/json");

            if (idx != "" && pass != "")
                request.Headers.Authorization = new AuthenticationHeaderValue("Basic", Convert.ToBase64String(Encoding.UTF8.GetBytes(idx + ":" + pass)));

            HttpResponseMessage response = await sharedClient.SendAsync(request);
            response.EnsureSuccessStatusCode();

            //deserialize
            var jsonResponse = await response.Content.ReadAsStringAsync();

            return jsonResponse;
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

            HttpResponseMessage response = await sharedClient.SendAsync(request);

            response.EnsureSuccessStatusCode();

            var jsonResponse = await response.Content.ReadAsStringAsync();
            return jsonResponse;
        }

        private async Task<string> GetAsyncWithAuth(string url, string content, Enrollment registrar) {
            HttpRequestMessage request = new HttpRequestMessage(HttpMethod.Get, url);

            request.Content = new StringContent(content, Encoding.UTF8);

            if (registrar != null)
                request.Headers.TryAddWithoutValidation("Authorization", GenerateAuthToken(registrar, content));

            HttpResponseMessage response = await sharedClient.SendAsync(request);

            response.EnsureSuccessStatusCode();

            var jsonResponse = await response.Content.ReadAsStringAsync();
            return jsonResponse;
        }

        /// <summary>
        /// Generates authorization token required for accessing fabric-ca APIs.
        /// </summary>
        /// <param name="registrar"></param>
        /// <param name="content"></param>
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
    }
}
