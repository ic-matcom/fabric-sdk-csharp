using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Text;
using System.Threading.Tasks;

namespace FabricCaClient {
    public class CAClient {
        // HttpClient lifecycle management best practices:
        // https://learn.microsoft.com/dotnet/fundamentals/networking/http/httpclient-guidelines#recommended-use
        //give error with ssl
        private static HttpClient sharedClient = new() {
            BaseAddress = new Uri("http://localhost:7054/api/v1/"),
        };

        public async Task<string> GetCaInfo() {
            using HttpResponseMessage response = await sharedClient.GetAsync("cainfo");
            
            response.EnsureSuccessStatusCode();

            var jsonResponse = await response.Content.ReadAsStringAsync();
            return jsonResponse;
        }
    }
}
