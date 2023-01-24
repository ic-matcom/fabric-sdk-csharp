using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Security.Cryptography.X509Certificates;

namespace FabricCaClient.HFBasicTypes {
    /// <summary>
    /// Interface to implement for PKI key creation/signing/verification
    /// </summary>
    public interface ICryptoSuite {
        KeyStore Store { get; set; }

        ICryptoSuiteFactory GetCryptoSuiteFactory();

        Properties GetProperties();

        void loadCACertificates(Collection<X509Certificate2> certificates);

        void loadCACertificatesAsBytes(Collection<byte[]> certificates);

        KeyPair KeyGen();

        byte[] Sign(KeyPair key, byte[] plainText);

        bool Verify(byte[] certificate, string signatureAlgorithm, byte[] signature, byte[] plainText);

        byte[] Hash(byte[] plainText);

        string GenerateCertificationRequest(string user, KeyPair keyPair);

        X509Certificate2 bytesToCertificate(byte[] certBytes);
    }
}
