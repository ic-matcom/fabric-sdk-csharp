using FabricCaClient.Crypto;
using Org.BouncyCastle.Crypto;
using System.Text;
using System.Security.Cryptography.X509Certificates;

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
        /// Constructor for CAService class
        /// </summary>
        /// <param name="cryptoPrimitives"></param>
        /// <param name="caEnpoint"></param>
        /// <param name="baseUrl"></param>
        /// <param name="caCertsPath"></param>
        /// <param name="caName"></param>
        public CAService(CryptoPrimitives cryptoPrimitives, string caEnpoint = "", string baseUrl = "", string caCertsPath = "", string caName = "") {
            if (cryptoPrimitives != null) {
                _cryptoPrimitives = cryptoPrimitives;
            }
            else {
                // to implement
                _cryptoPrimitives = new CryptoPrimitives();
            }

            _caClient = new CAClient(_cryptoPrimitives, caEnpoint, baseUrl, caCertsPath, caName);
        }

        /// <summary>
        /// Enrolls a registered user in order to receive a signed X509 certificate
        /// </summary>
        /// <param name="enrollmentId"></param>
        /// <param name="enrollmentSecret"></param>
        /// <param name="csr"></param>
        /// <param name="profile"></param>
        /// <param name="attrRqs"></param>
        /// <returns></returns>
        public async Task<Enrollment> Enroll(string enrollmentId, string enrollmentSecret, string csr = "", string profile = "", string attrRqs = "") {
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
            // check crs codification

            Tuple<string, string> certs = await _caClient.Enroll(enrollmentId, enrollmentSecret, csr, profile, attrRqs);

            // check pkey isnt use where csr is provided
            return new Enrollment(keyPair, certs.Item1, certs.Item2, this);
        }

        /// <summary>
        /// Reenrolls an identity.
        /// </summary>
        /// <param name="currentUser"></param>
        /// <param name="attrRqs"></param>
        /// <returns></returns>
        public async Task<Enrollment> Reenroll(Enrollment currentUser, string attrRqs = "") {
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
        /// Registers an identity
        /// </summary>
        /// <param name="enrollmentId"></param>
        /// <param name="enrollmentSecret"></param>
        /// <param name="maxEnrollments"></param>
        /// <param name="attrs"></param>
        /// <param name="registrar"></param>
        /// <param name="role"></param>
        /// <param name="affiliatiton"></param>
        /// <returns></returns>
        public async Task<string> Register(string enrollmentId, string enrollmentSecret, int maxEnrollments, string attrs, Enrollment registrar, string role = "", string affiliatiton = "") {
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
            // check ca name
            if (!revokingReasons.Contains(reason))
                throw new Exception("Revocation reason not found. Please provide one that belongs to those listed in the HF CA specifications");
            return await _caClient.Revoke(enrollmentId, aki, serial, reason, genCrl, registrar);
        }

        public async Task<string[]> GetCertificates(Enrollment registrar) {
            return await _caClient.GetCertificates(registrar);
        }
    }
}
