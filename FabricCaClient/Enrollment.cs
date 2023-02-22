using Org.BouncyCastle.Crypto;

namespace FabricCaClient {
    public class Enrollment {
        public AsymmetricKeyParameter PrivateKey { get; set; } //llevar a string
        public string Cert { get; private set; }
        public string CAChainCert { get; private set; }
        public CAService CAService { get; private set; } // remove this item

        public Enrollment(AsymmetricKeyParameter privateKey, string cert, string caChainCert, CAService cAService) {
            PrivateKey = privateKey;
            Cert = cert;
            CAChainCert = caChainCert;
            CAService = cAService;
        }
    }
}