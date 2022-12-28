
using FabricCaClient.HFBasicTypes;
using Microsoft.Win32;
using System.Linq;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;

namespace FabricCaClient
{
    /// <summary>
    ///  A class that encapsulates a set of methods to communicate with Hyperledger Fabric (HF)'s Certificate Authority (CA).
    /// </summary>
    public class CAClient {
        public ICryptoSuite CryptoSuite { get; set; }

        public static readonly string HFCA_CONTEXT_ROOT = "/api/v1/";

        private readonly string url; // find a more suitable name

        private static readonly string HFCA_REGISTER = HFCA_CONTEXT_ROOT + "register";
        private CryptoPrimitives cryptoPrimitives;
        private bool isSSL;
        private Properties properties;
        private KeyStore caStore;

        /// <summary>
        /// Enrolls an identity
        /// </summary>
        /// /// <param name="x"></param>
        /// <returns></returns>
        public void Enroll() { }

        /// <summary>
        /// Reenrolls an identity
        /// </summary>
        public void Reenroll() { }

        private void SetUpSSL() {
            // basically what is done here is the setting of the caStore
            //if (cryptoPrimitives == null) {
            //    try {
            //        cryptoPrimitives = new CryptoPrimitives();
            //        cryptoPrimitives.init();
            //    }
            //    catch (Exception exc) {
            //        throw new Exception("Error while setting crypto primitives", exc);
            //    }
            //}

            if (CryptoSuite == null) {
                try {
                    CryptoSuite = Factory.GetCryptoSuite();
                }
                catch (Exception exc) {
                    throw new Exception(exc.Message, exc);
                }
            }

            //if (isSSL == null && registry == null) {
            //if (!properties.Contains("pemBytes") && !properties.Contains("pemFile"){
            //    byte[] permbytes = (byte[])
            //    }
            //}
            if (isSSL && caStore == null) {
                if ( !properties.Contains("pemBytes") && !properties.Contains("pemFile")){
                    Console.WriteLine("SSL with no CA certificates in either pemBytes or pemFile");
                }

                try {
                    if (properties.Contains("pemBytes"))
                        CryptoSuite.Store.AddCertificate(properties["pemBytes"]);
                    if (properties.Contains("pemFile")) {
                        string pemFile = properties["pemFile"];
                        if (!string.IsNullOrEmpty(pemFile)) {
                            Regex pattern = new Regex("[ \t]*,[ \t]*");
                            string[] pems = pattern.Split(pemFile);
                            foreach (string pem in pems) {
                                if (!string.IsNullOrEmpty(pem)) {
                                    string fname = Path.GetFullPath(pem);
                                    try {
                                        CryptoSuite.Store.AddCertificate(File.ReadAllText(fname));
                                    }
                                    catch (IOException) {
                                        throw new Exception($"Unable to add cetificate, can't open certificate file {pem}");
                                    }
                                }
                            }
                        }
                    }
                    caStore = CryptoSuite.Store;
                }
                catch( Exception exc) {
                    Console.WriteLine(exc.Message);
                    throw new Exception(exc.Message, exc);
                }
            }
            // socket stuff. some funcitonalities are provided to java by apache. Alternatives need to be found for c#
        }

        private JsonObject HttpPost(string url, string body, IUser registrar) {
            throw new NotImplementedException();
            return new JsonObject();
        }

        /// <summary>
        /// Registers an identity
        /// </summary>
        /// /// <param name="x"></param>
        /// <returns></returns>
        public string Register(RegistrationRequest registrationRequest, IUser registrar) {
            if (CryptoSuite == null) // set in cstr
                                     // customize later with proper exceptions
                throw new Exception("Crypto primitives not set");

            if (registrationRequest == null) // ask for enrollmentID after the interface have been defined
                throw new ArgumentException("Enrollment id not set in registration request");

            if (registrar == null)
                throw new ArgumentException("Registrar should be a valid member");

            SetUpSSL();

            try {
                string body = registrationRequest.ToJson();
                // validate if is neccessary to add token
                JsonObject response = HttpPost(url + HFCA_REGISTER, body, registrar);
                string secret = response["secret"]?.GetValue<string>();

                if (secret == null)
                    throw new Exception("Secret not found in response");

                return secret;
            }
            catch (Exception exc) {
                throw new Exception("Error while registering the user {registrar.Name} with url: {url}", exc);
            }
        }

        /// <summary>
        /// Revokes an identity
        /// </summary>
        public void Revoke() { }
    }
}