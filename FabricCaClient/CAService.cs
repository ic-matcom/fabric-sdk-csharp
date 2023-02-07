using FabricCaClient.Crypto;
using Newtonsoft.Json.Linq;
using Org.BouncyCastle.Crypto;
using System;
using System.Collections.Generic;
using System.Dynamic;
using System.Linq;
using System.Net.Http.Headers;
using System.Text;
using System.Threading.Tasks;
using System.Security.Cryptography.X509Certificates;

namespace FabricCaClient
{
    /// <summary>
    /// A class that serves as an interface to the CaClient that communicates with the CA
    /// </summary>
    public class CAService {
        private CryptoPrimitives _cryptoPrimitives;
        private CAClient _caClient;

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
                keyPair = new AsymmetricCipherKeyPair(null, null) ;// ver si esta ok trabajar con estos tipos asymCkp o resulta mejor implementar uno con strings
            }
            // check crs codification

            Tuple<string, string> certs = await _caClient.Enroll(enrollmentId, enrollmentSecret, csr, profile, attrRqs);

            // check pkey isnt use where csr is provided
            return new Enrollment(keyPair, certs.Item1, certs.Item2, this);
        }

        /// <summary>
        /// Reenrolls an identity
        /// </summary>
        /// <param name="currentUser"></param>
        /// <param name="attrRqs"></param>
        /// <returns></returns>
        public async Task<Enrollment> Reenroll(Enrollment currentUser, string attrRqs = "") {
            // Check for  attrReqs spected format
            AsymmetricCipherKeyPair privateKey = _cryptoPrimitives.GenerateKeyPair();
            
            // Convert pem to cert in order to access its Subject element (Deserialize the certificate from PEM encoded data.)
            X509Certificate2 x509Cert = new X509Certificate2(Encoding.UTF8.GetBytes(currentUser.Cert));

            // get Subject's Common name from certificate 
            var certCN = (x509Cert.Subject.Split(',')[0].Split('=')[1]).ToString();
            
            // get new certificate signing request
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
        /// Revokes an identity
        /// </summary>
        /// <param name="enrollmentId"></param>
        /// <param name="aki"></param>
        /// <param name="serial"></param>
        /// <param name="reason"></param>
        /// <param name="genCrl"></param>
        /// <param name="registrar"></param>
        /// <returns></returns>
        public async Task<Tuple<string, string>> Revoke(string enrollmentId, string aki, string serial, string reason, bool genCrl, Enrollment registrar) {
            // check ca name
            return await _caClient.Revoke(enrollmentId, aki, serial, reason, genCrl, registrar);
        }
    }

}
