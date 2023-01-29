using Newtonsoft.Json.Linq;
using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Reflection;
using System.Runtime;
using System.Text;
using System.Threading.Tasks;
using System.Xml.Linq;

namespace FabricCaClient {
    /// <summary>
    /// A class that encapsulates a set of methods to communicate with Hyperledger Fabric (HF)'s Certificate Authority (CA).
    /// </summary>
    public class CAClient {
        // The available paths and operations for the API as described in https://github.com/hyperledger/fabric-ca/blob/main/swagger/swagger-fabric-ca.json.
        private static string DEFAULT_CA_ENDPOINT = "http://localhost:7054";
        private static readonly string DEFAULT_CA_BASE_URL = "/api/v1/";

        private static readonly string CA_URL_ENROLL = "enroll";
        private static readonly string CA_URL_REGISTER =  "register";
        private static readonly string CA_URL_REENROLL = "reenroll";
        private static readonly string CA_URL_REVOKE = "revoke";
        private static readonly string CA_URL_INFO = "cainfo";
        private static readonly string CA_URL_GENCRL = "gencrl";
        private static readonly string CA_URL_CERTIFICATE = "certificates";
        private static readonly string CA_URL_IDEMIXCRED = "idemix/credential";

        // HttpClient lifecycle management best practices:
        // https://learn.microsoft.com/dotnet/fundamentals/networking/http/httpclient-guidelines#recommended-use
        // returns error with ssl
        private static HttpClient sharedClient;

        public CAClient(string caEnpoint = "") {
            if (caEnpoint != "")
                DEFAULT_CA_ENDPOINT = caEnpoint;

            var handler = new SocketsHttpHandler {
                PooledConnectionLifetime = TimeSpan.FromMinutes(15) // Recreate every 15 minutes
            };
            sharedClient = new HttpClient(handler) {
                BaseAddress = new Uri(DEFAULT_CA_ENDPOINT + DEFAULT_CA_BASE_URL),
            };
        }

        /// <summary>
        /// Ask for ca basic info
        /// </summary>
        /// <returns></returns>
        public async Task<string> GetCaInfo() {
            return await GetAsync(CA_URL_INFO);
        }

        /// <summary>
        /// Enrolls an identity
        /// </summary>
        /// /// <param name="x"></param>
        /// <returns></returns>
        public async Task<string> Enroll(string enrollmentId, string enrollmentSecret, string csr, string profile = "", string attrRqs = "") {
            if (enrollmentId == "" || enrollmentSecret == "" || csr == "")
                throw new ArgumentException($"Missing required parameters: enrollmentId-{enrollmentId}, enrollmentSecret-{enrollmentSecret} and csr-{csr} are all required");

            // consider creating a class to manage this elements in the future( with a toJson method)
            // var jsontent = JsonContent.Create(
            //    new {
            //        certificate_request = csr,
            //        profile = profile,
            //        attr_reqs = attrRqs
            //    });

            // adding this values only if not null
            JObject jsonBody = new JObject();
            jsonBody.Add(new JProperty("csr", csr));
            if (profile != "")
                jsonBody.Add(new JProperty("profile", profile));
            if (attrRqs != "")// attrRqs should already be a JArray of JObjects
                jsonBody.Add(new JProperty("attr_reqs", attrRqs));

            // get the result field which is Base64-encoded PEM

            var jsonResponse =  await PostAsync(CA_URL_ENROLL, jsonBody.ToString(Formatting.None), enrollmentId, enrollmentSecret);

            JObject jsonst = JObject.Parse(jsonResponse);
            bool success = jsonst["success"]?.Value<bool>() ?? false;
            if (success) {
                JObject result = jsonst["result"] as JObject;
                if (result != null) {
                    //verify following converison as ToUTF8String() is no longer available and was substituted by toString
                    string signedPem = Convert.FromBase64String(result["Cert"]?.Value<string>() ?? "").ToString();
                    return signedPem;// CAChain too
                }
            }
            return "Error in enrollmente request";
        }

        /// <summary>
        /// Reenrolls an identity
        /// </summary>
        /// <param name="enrollmentId"></param>
        /// <param name="enrollmentSecret"></param>
        /// <returns></returns>
        public async Task<string> Reenroll(string enrollmentId = "", string enrollmentSecret = "") {
            return await PostAsync(CA_URL_REENROLL, "");
        }

        /// <summary>
        /// Registers an identity
        /// </summary>
        /// <returns></returns>
        public async Task<string> Register(string enrollmentId = "", string enrollmentSecret = "") {
            return await PostAsync(CA_URL_REGISTER, "");
        }

        /// <summary>
        /// Revokes an identity
        /// </summary>
        /// <returns></returns>
        public async Task<string> Revoke() {
            return await PostAsync(CA_URL_REVOKE, "");
        }

        static async Task<string> GetAsync(string url) {
            // as per the using keyword specification, this object is disposed correctly after going out of the scope definition
            using HttpResponseMessage response = await sharedClient.GetAsync(url);

            response.EnsureSuccessStatusCode();

            var jsonResponse = await response.Content.ReadAsStringAsync();
            return jsonResponse;
        }
        //static async Task<string> PostAsync(string url, JsonContent content, string idx = "", string pass = "") {
        //    HttpRequestMessage request = new HttpRequestMessage(HttpMethod.Post, url);

        //    request.Content = content;

        //    if (idx != "" && pass != "")
        //        request.Headers.Authorization = new AuthenticationHeaderValue(idx, pass);

        //    HttpResponseMessage response = await sharedClient.SendAsync(request);

        //    response.EnsureSuccessStatusCode();

        //    //deserialize
        //    var jsonResponse = await response.Content.ReadAsStringAsync();
        //    return jsonResponse;
        //}

        static async Task<string> PostAsync(string url, string content, string idx = "", string pass = "") {
            HttpRequestMessage request = new HttpRequestMessage(HttpMethod.Post, url);

            request.Content = new StringContent(content, Encoding.UTF8);

            if (idx != "" && pass != "")
                request.Headers.Authorization = new AuthenticationHeaderValue(idx, pass);

            HttpResponseMessage response = await sharedClient.SendAsync(request);

            response.EnsureSuccessStatusCode();

            //deserialize
            var jsonResponse = await response.Content.ReadAsStringAsync();
            return jsonResponse;
        }
    }
}
