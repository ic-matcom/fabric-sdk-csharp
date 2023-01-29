using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Text;
using System.Threading.Tasks;

namespace FabricCaClient {
    public class CAClient {
        // The available paths and operations for the API as described in https://github.com/hyperledger/fabric-ca/blob/main/swagger/swagger-fabric-ca.json.
        private static string DEFAULT_CA_ENDPOINT = "http://localhost:7054";
        private static readonly string DEFAULT_CA_BASE_URL = "/api/v1/";

        private static readonly string CA_URL_ENROLL = DEFAULT_CA_BASE_URL + "enroll";
        private static readonly string CA_URL_REGISTER = DEFAULT_CA_BASE_URL + "register";
        private static readonly string CA_URL_REENROLL = DEFAULT_CA_BASE_URL + "reenroll";
        private static readonly string CA_URL_REVOKE = DEFAULT_CA_BASE_URL + "revoke";
        private static readonly string CA_URL_INFO = DEFAULT_CA_BASE_URL + "cainfo";
        private static readonly string CA_URL_GENCRL = DEFAULT_CA_BASE_URL + "gencrl";
        private static readonly string CA_URL_CERTIFICATE = DEFAULT_CA_BASE_URL + "certificates";
        private static readonly string CA_URL_IDEMIXCRED = DEFAULT_CA_BASE_URL + "idemix/credential";

        // HttpClient lifecycle management best practices:
        // https://learn.microsoft.com/dotnet/fundamentals/networking/http/httpclient-guidelines#recommended-use
        // give error with ssl
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

        public async Task<string> GetCaInfo() {
            return await GetAsync("cainfo");
        }

        public async Task<string> Enroll(string enrollmentId = "", string enrollmentSecret = "") {
            return await PostAsync(CA_URL_ENROLL, "");
        }

        static async Task<string> GetAsync(string url) {
            // as per the using keyword specification, this object is disposed correctly after going out of the scope definition
            using HttpResponseMessage response = await sharedClient.GetAsync(url);

            response.EnsureSuccessStatusCode();

            var jsonResponse = await response.Content.ReadAsStringAsync();
            return jsonResponse;
        }

        static async Task<string> PostAsync(string url, string content) {
            using HttpResponseMessage response = await sharedClient.PostAsync(url,new StringContent(content));

            response.EnsureSuccessStatusCode();

            var jsonResponse = await response.Content.ReadAsStringAsync();
            return jsonResponse;
        }
    }
}
