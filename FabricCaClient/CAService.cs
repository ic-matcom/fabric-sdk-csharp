using FabricCaClient.Crypto;
using Org.BouncyCastle.Crypto;
using System.Text;
using System.Security.Cryptography.X509Certificates;
using System;
using Org.BouncyCastle.Asn1.X509;

namespace FabricCaClient
{
    /// <summary>
    /// A class that serves as an interface to the CaClient that communicates with the CA
    /// </summary>
    public class CAService {
        private CryptoPrimitives _cryptoPrimitives;
        private CAClient _caClient;
        private string[] revokingReasons = { "unspecified", "keyCompromise", "cACompromise", "affiliationChanged", "superseded", "cessationOfOperation", "certificateHold", "removeFromCRL", "privilegeWithdrawn", "aACompromise" };

        // to test
        public async Task<string> GetCaInfo() {
            return await _caClient.GetCaInfo();
        }

        /// <summary>
        /// Constructor for CAService class.
        /// </summary>
        /// <param name="cryptoPrimitives">An instance of a Crypto Suite for PKI key creation/signing/verification. Provide null for use of default implementation.</param>
        /// <param name="caEnpoint">Http URL for the Fabric's certificate authority services endpoint.</param>
        /// <param name="baseUrl">Ca url where the base api resides. (Default "/api/v1/").</param>
        /// <param name="caCertsPath">Local ca certs path (for trusted root certs).</param>
        /// <param name="caName">Name of the CA to direct traffic to within server as FabricCa servers support multiple Certificate Authorities from a single server.</param>
        public CAService(CryptoPrimitives cryptoPrimitives, string caEnpoint = "", string baseUrl = "", string caCertsPath = "", string caName = "") {
            if (cryptoPrimitives != null) {
                _cryptoPrimitives = cryptoPrimitives;
            }
            else {
                _cryptoPrimitives = new CryptoPrimitives();
            }

            _caClient = new CAClient(_cryptoPrimitives, caEnpoint, baseUrl, caCertsPath, caName);
        }

        /// <summary>
        /// Enrolls a registered user in order to receive a signed X509 certificate.
        /// </summary>
        /// <param name="enrollmentId">Unique ID to use for enrollment, previusly registered with register call to the ca.</param>
        /// <param name="enrollmentSecret">The secret associated with the enrollment ID.</param>
        /// <param name="csr">A PEM-encoded string containing the CSR (Certificate Signing Request) based on PKCS #10. (Optional parameter as it can be generated from enrollmentId and secret).</param>
        /// <param name="profile">The name of the signing profile to use when issuing the certificate.'tls' for a TLS certificate; otherwise, an enrollment certificate is issued.</param>
        /// <param name="attrRqs">A dictionary with attribute requests to be placed into the enrollment certificate. <remarks>Expected format is: "string attrName -> bool optional (wether or not the attr is required)".</remarks></param>
        /// <returns>An <see cref="Enrollment"/> instance with corresponding keypair (generated if csr not provided), enrollment and CA certificates. </returns>
        public async Task<Enrollment> Enroll(string enrollmentId, string enrollmentSecret, string csr = "", string profile = "", Dictionary<string, bool> attrRqs = null) {
            // this could be checked here    
            // if (enrollmentId == "" || enrollmentSecret == "" )

            // check attReqs format, is possible one need to reformat here to give the spected form

            AsymmetricCipherKeyPair keyPair;
            if (csr == "") {
                keyPair = _cryptoPrimitives.GenerateKeyPair();
                csr = _cryptoPrimitives.GenerateCSR(keyPair, enrollmentId);
            }
            else {
                keyPair = new AsymmetricCipherKeyPair(null, null);// ver si esta ok trabajar con estos tipos asymCkp o resulta mejor implementar uno con strings
            }

            Tuple<string, string> certs = await _caClient.Enroll(enrollmentId, enrollmentSecret, csr, profile, attrRqs);

            // check pkey isnt use where csr is provided
            return new Enrollment(keyPair, certs.Item1, certs.Item2, this);
        }

        /// <summary>
        /// Reenrolls an identity in cases where his existing enrollment certificate is about to expire, or it has been compromised.
        /// </summary>
        /// <param name="currentUser">The identity of the user that holds the existing enrollment certificate.</param>
        /// <param name="attrRqs">A dictionary with attribute requests to be placed into the enrollment certificate. <remarks>Expected format is: "string attrName -> bool optional (wether or not the attr is required)".</remarks></param>
        /// <returns>A new <see cref="Enrollment"/> instance with corresponding keypair, enrollment and CA certificates. </returns>
        public async Task<Enrollment> Reenroll(Enrollment currentUser, Dictionary<string, bool> attrRqs = null) {
            // Check for  attrReqs spected format
            AsymmetricCipherKeyPair privateKey = _cryptoPrimitives.GenerateKeyPair();

            // Convert pem to cert in order to access its Subject element (Deserialize the certificate from PEM encoded data.)
            X509Certificate2 x509Cert = new X509Certificate2(Encoding.UTF8.GetBytes(currentUser.Cert));

            // Get Subject's Common name from certificate 
            var certCN = (x509Cert.Subject.Split(',')[0].Split('=')[1]).ToString();

            // Get new certificate signing request
            string csr = _cryptoPrimitives.GenerateCSR(privateKey, certCN);

            Tuple<string, string> certs = await _caClient.Reenroll(currentUser, csr, attrRqs);

            return new Enrollment(privateKey, certs.Item1, certs.Item2, this);
        }

        /// <summary>
        /// Registers an identity.
        /// </summary>
        /// <param name="enrollmentId">The enrollment ID which uniquely identifies an identity.</param>
        /// <param name="enrollmentSecret">The enrollment secret. If not provided, a random secret is generated.</param>
        /// <param name="maxEnrollments">The maximum number of times the secret can be reused to enroll.</param>
        /// <param name="attrs">An array of attribute names and values to give to the registered identity. 
        /// <remarks>Expected format is for each item is: Tuple{string name, string value, bool ecert}, 
        /// indicating name an value of the attribute and wether or not it should be included in an enrollment certificate by default.</remarks> 
        /// </param>
        /// <param name="registrar">The registrar that performs the operation.</param>
        /// <param name="role">The type of the identity (e.g. *user*, *app*, *peer*, *orderer*, etc). Default role is client.</param>
        /// <param name="affiliatiton">The affiliation of the new identity. If no affliation is provided, the affiliation of the registrar is used.</param>
        /// <returns>A string representing the enrollment secret of the newly registered identity.</returns>
        public async Task<string> Register(string enrollmentId, string enrollmentSecret, int maxEnrollments, Tuple<string, string, bool>[] attrs, Enrollment registrar, string role = "", string affiliatiton = "") {
            // check enrollmentScret is no ""
            return await _caClient.Register(enrollmentId, enrollmentSecret, maxEnrollments, attrs, registrar, role, affiliatiton);
        }

        /// <summary>
        /// Revokes an identity or a given certificate. When revoking an identity all the relates certificaters are revoked, and further enroll calls with its id will be denied.
        /// </summary>
        /// <param name="enrollmentId">Id of the identity to revoke</param>
        /// <param name="aki">Authority Key Identifier (hex encoded) for the certificate to revoke. 
        /// <remarks>
        /// Required when revoking a certitificate, otherwise shoud be set to "".
        /// </remarks>
        /// </param>
        /// <param name="serial"> Serial number (hex encoded) for the certificate to revoke.
        /// <remarks>
        /// Required when revoking a certitificate, otherwise shoud be set to "".
        /// </remarks></param>
        /// <param name="reason">A reason for the revocation. Please visit <see href="https://www.rfc-editor.org/rfc/rfc5280.html#section-5.3.1">RFC 6960</see> for a list of correct values according to HF CA specifications.</param>
        /// <param name="genCrl">A boolean to indicate whether or not to generate a Certificate Revocation List.</param>
        /// <param name="registrar">The instance of a Enrollment encapsulating the identity that perfoms the revocation.</param>
        /// <returns>A base64 encoded PEM-encoded CRL.</returns>
        public async Task<string> Revoke(string enrollmentId, string aki, string serial, string reason, bool genCrl, Enrollment registrar) {
            if (!revokingReasons.Contains(reason))
                throw new Exception("Revocation reason not found. Please provide one that belongs to those listed in the HF CA specifications");
            return await _caClient.Revoke(enrollmentId, aki, serial, reason, genCrl, registrar);
        }
    }
}
