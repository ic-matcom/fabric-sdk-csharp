using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;

namespace FabricCaClient.Crypto {
    /// <summary>
    /// Interface to implement for PKI key creation/signing/verification
    /// </summary>
    public interface ICryptoSuite {
        // CryptoSuite(Interface)
        //generate_key
        //deriveKey
        //importKey
        //getKey
        //hash
        //encrypt
        //decrypt
        //sign
        //verify

        //byte[] Sign(KeyPair key, byte[] plainText);

        bool Verify(byte[] certificate, string signatureAlgorithm, byte[] signature, byte[] plainText);

        byte[] Hash(byte[] plainText);

        //string GenerateCertificationRequest(string user, KeyPair keyPair);
        string GenerateCSR(string privateKey, string enrollmentId) {
            throw new NotImplementedException();
        }

        // GenerateKey
        string GeneratePrivateKey() {
            throw new NotImplementedException();
        }
    }
}
