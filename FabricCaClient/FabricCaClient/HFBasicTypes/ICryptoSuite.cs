using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace FabricCaClient.HFBasicTypes {
    public interface ICryptoSuite {
        KeyStore Store { get; set; }

        ICryptoSuiteFactory GetCryptoSuiteFactory();

        Properties GetProperties();

        KeyValuePair KeyGen();

        byte[] Sign(KeyPair key, byte[] plainText);

        bool Verify(byte[] certificate, string signatureAlgorithm, byte[] signature, byte[] plainText);

        byte[] Hash(byte[] plainText);

        string GenerateCertificationRequest(string user, KeyPair keyPair);
    }
}
