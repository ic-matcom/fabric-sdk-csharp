namespace FabricCaClient {
    public class Enrollment {
        public string PrivateKey { get; private set; }
        public string Cert { get; private set; }
        public string CAChainCert { get; private set; }
        public CAService CAService { get; private set; } // remove this item

        public Enrollment(string privateKey, string cert, string caChainCert, CAService cAService) {
            PrivateKey = privateKey;
            Cert = cert;
            CAChainCert = caChainCert;
            CAService = cAService;
        }
    }
}