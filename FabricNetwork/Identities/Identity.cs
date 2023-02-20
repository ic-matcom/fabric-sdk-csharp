using Newtonsoft.Json.Linq;
using Org.BouncyCastle.Crypto;

namespace FabricNetwork.Identities {
    public interface Identity {

        /// <summary>
        /// Retrieve the member services provider to which this identity is associated.
        /// </summary>
        /// <returns>A string representing the msp id.</returns>
        public string GetMspId();

        /// <summary>
        /// Retrieve the identitity's certificate.
        /// </summary>
        /// <returns></returns>
        public string GetCertificate();

        /// <summary>
        /// Retrieve the identitity's private key.
        /// </summary>
        /// <returns></returns>
        public AsymmetricKeyParameter GetPrivateKey();

        /// <summary>
        /// Converts identity to jason format for proper storage.
        /// </summary>
        /// <returns></returns>
        public JObject ToJson();
    }
}