using FabricCaClient;

namespace TestSdkCSharp {
    internal class Program {
        static async Task Main(string[] args) {
            CAClient caclient = new CAClient();
            Console.WriteLine("Intialized");
            var jsonResponse = await caclient.GetCaInfo();
            Console.WriteLine($"{jsonResponse}\n");
        }
    }
}