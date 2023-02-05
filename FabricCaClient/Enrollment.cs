using Org.BouncyCastle.Crypto;

namespace FabricCaClient {
    public class Enrollment {
        public AsymmetricCipherKeyPair KeyPair { get; private set; }
        public string Cert { get; private set; }
        public string CAChainCert { get; private set; }
        public CAService CAService { get; private set; } // remove this item

        public Enrollment(AsymmetricCipherKeyPair privateKey, string cert, string caChainCert, CAService cAService) {
            KeyPair = privateKey;
            Cert = cert;
            CAChainCert = caChainCert;
            CAService = cAService;
        }
    }
}