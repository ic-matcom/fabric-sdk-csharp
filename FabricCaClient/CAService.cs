using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http.Headers;
using System.Text;
using System.Threading.Tasks;

namespace FabricCaClient {
    /// <summary>
    /// A class that serves as an interface to the CaClient that communicates with the CA
    /// </summary>
    internal class CAService {
        private CryptoPrimitives cryptoPrimitives;
        private CAClient caClient;

        /// <summary>
        /// Constructor for CAService class
        /// </summary>
        /// <param name="cryptoPrim"></param>
        /// <param name="caEnpoint"></param>
        /// <param name="baseUrl"></param>
        /// <param name="_caCertsPath"></param>
        /// <param name="_caName"></param>
        public CAService(CryptoPrimitives cryptoPrim, string caEnpoint = "", string baseUrl = "", string _caCertsPath = "", string _caName = "") {
            if (cryptoPrim != null) {
                cryptoPrimitives = cryptoPrim;
            }
            else {
                // to implement
                cryptoPrimitives = new CryptoPrimitives();
            }

            caClient = new CAClient(cryptoPrimitives, caEnpoint, baseUrl, _caCertsPath, _caName);
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
        public async Task<Enrollment> Enroll(string enrollmentId, string enrollmentSecret, string csr, string profile = "", string attrRqs = "") {
            // this could be checked here    
            // if (enrollmentId == "" || enrollmentSecret == "" )

            // check attReqs format, is possible one need to reformat here to give the spected form

            string privateKey = "";
            if (csr == "") {
                // both methods below are still to ve implemented
                privateKey = cryptoPrimitives.GeneratePrivateKey();
                csr = cryptoPrimitives.GenerateCSR(privateKey, enrollmentId);
            }
            // check crs codification

            Tuple<string, string> certs = await caClient.Enroll(enrollmentId, enrollmentSecret, csr, profile, attrRqs);

            // check pkey isnt use where csr is provided
            return new Enrollment(privateKey, certs.Item1, certs.Item2, this);
        }

        /// <summary>
        /// Reenrolls an identity
        /// </summary>
        /// <param name="currentUser"></param>
        /// <param name="attrRqs"></param>
        /// <returns></returns>
        public async Task<Enrollment> Reenroll(Enrollment currentUser, string attrRqs = "") {
            // Check for  attrReqs spected format
            // Implement new type Cert or use defatul X509_2(
            string cert = currentUser.Cert;
            string privateKey = cryptoPrimitives.GeneratePrivateKey();
            // Add Subject to Cert element
            string csr = cryptoPrimitives.GenerateCSR(privateKey, cert.Subject);

            Tuple<string, string> certs = await caClient.Reenroll(currentUser, csr, attrRqs);

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
            return await caClient.Register(enrollmentId, enrollmentSecret, maxEnrollments, attrs, registrar, role, affiliatiton);
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
            return await caClient.Revoke(enrollmentId, aki, serial, reason, genCrl, registrar);
        }
    }

}
