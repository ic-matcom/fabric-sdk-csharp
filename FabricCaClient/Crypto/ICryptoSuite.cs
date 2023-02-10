using Org.BouncyCastle.Crypto;
using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;

namespace FabricCaClient.Crypto {
    /// <summary>
    /// Interface that encapsulates algorithms for digital signatures and encryption.
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

        /// <summary>
        /// Generates a key pair with Public and Private keys according to a given algorithm.
        /// </summary>
        /// <returns>An AsymmetricCipherKeyPair instance with Public and Private keys generated.</returns>
        AsymmetricCipherKeyPair GenerateKeyPair();

        ///// <summary>
        ///// Hashes a given message.
        ///// </summary>
        ///// <param name="plainText">Message to hash.</param>
        ///// <returns></returns>
        //byte[] Hash(byte[] plainText);

        /// <summary>
        /// Sign the data.
        /// </summary>
        /// <param name="keyPair">Key pair with private key to use for signing.</param>
        /// <param name="messageToSign">Message to be signed with a given hashing function.</param>
        /// <returns>Signed message.</returns>
        public string Sign(AsymmetricCipherKeyPair keyPair, byte[] messageToSign);

        ///// <summary>
        ///// Verifies the signature.
        ///// </summary>
        ///// <param name="certificate"></param>
        ///// <param name="signatureAlgorithm"></param>
        ///// <param name="signature"></param>
        ///// <param name="plainText"></param>
        ///// <returns></returns>
        //bool Verify(byte[] certificate, string signatureAlgorithm, byte[] signature, byte[] plainText);

        /// <summary>
        /// Generates a Certificate signing request according to the given keyPair and subject.
        /// </summary>
        /// <param name="keyPair">An AsymmetricCipherKeyPair instance with public and private keys.</param>
        /// <param name="subjectName">The subjects name to register in the certificate.</param>
        /// <returns>A 64 base encode pem certificate signing request.</returns>
        string GenerateCSR(AsymmetricCipherKeyPair keyPair, string subjectName);

    }
}
