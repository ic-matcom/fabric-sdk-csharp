using FabricCaClient;
using FabricCaClient.Crypto;
using FabricNetwork.Identities;
using FabricNetwork.Wallets;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.X509;
using System.Runtime.ConstrainedExecution;
using System.Text;
using System.Text.RegularExpressions;

namespace TestSdkCSharp
{
    internal class Program {
        static async Task Main(string[] args) {
            //CAClient caclient = new CAClient();
            //Console.WriteLine("Intialized");
            //var jsonResponse = await caclient.GetCaInfo();
            //Console.WriteLine($"{jsonResponse}\n");

            //CAService caService = new CAService(null, caName: "ca-org1");
            //Console.WriteLine("Initilized entity");
            //var jsonResponse = await caService.GetCaInfo();
            //Console.WriteLine($"{jsonResponse}\n");
            // catch exception when server ir not up
            //No connection could be made because the target machine actively refused it.                                              

            #region Test Enroll
            //Enrollment enr = await caService.Enroll("admin", "adminpw");
            //PrintEnrollmentInstance(enr);
            #endregion Test Enroll

            #region Test Enroll with atts
            //var attrs = new Dictionary<string, bool> { { "foo", true}, { "bar", true } };
            //Enrollment enr = await caService.Enroll("admin", "adminpw", attrRqs: attrs);
            //PrintEnrollmentInstance(enr);
            #endregion Test Enroll

            #region Test Reenroll
            //Enrollment reenroll = await caService.Reenroll(enr);
            //PrintEnrollmentInstance(reenroll);
            #endregion Test reenroll

            #region Test Reenroll with atts
            //var attrs = new Dictionary<string, bool> { { "foo", true }, { "bar", true } };
            //Enrollment reenroll = await caService.Reenroll(enr, attrRqs: attrs);
            //PrintEnrollmentInstance(reenroll);
            #endregion Test reenroll with atts

            #region Test Register
            //string secret = await caService.Register("appUser", "", 10, "", enr);PTsCHyhTxcJc
            //string secret = await caService.Register("appUser1", "", 10, "", enr);//yyWUYRvGzxyE
            //string secret = await caService.Register("appUser2", "", 10, "", enr);//QxNJJuSPzcHh
            //string secret = await caService.Register("appUser3", "", 10, "", enr);//EclVNfPWZEsF
            //string secret = await caService.Register("appUser10", "", 10, "", enr);//

            #region Test Enroll
            //Enrollment enr2 = await caService.Enroll("appUser10", secret);
            //PrintEnrollmentInstance(enr2);
            #endregion Test Enroll
            #endregion Test Register

            #region Test Register with atts
            //var attrs = new Tuple<string, string, bool>[] { new Tuple<string, string, bool>("foo", "bar", false), new Tuple<string, string, bool>("foo1", "bar1", true) };
            //string secret = await caService.Register("appUser72", "", 10, attrs: attrs, enr);
            #endregion Test Register with atts

            #region Test Revoke
            string userId = "appUser70";//12 con 20 ok, pero de 10 a 14 daba error con los dos tipos de autorizacion

            #region get cert info
            //var certs = await caService.GetCertificates(enr);
            //Console.WriteLine("Certtificates:");
            //Console.WriteLine(certs);
            #endregion get cert info

            //var con = await TestRevocation("admin", "adminpw", "appUser55", "", caEndpoint: "https://localhost:7054", caCertsPath: "ca-cert.pem");
            //Console.WriteLine("Exit revocation method");
            //Console.WriteLine(con);
            #endregion Test Revoke

            #region Test Enroll with csr
            //CAService caService = new CAService(null, caName: "ca-org1");
            //Console.WriteLine("Initilized entity");
            //var cryptoPrimitives = new CryptoPrimitives();
            //var keyPair = cryptoPrimitives.GenerateKeyPair();
            //var csr = cryptoPrimitives.GenerateCSR(keyPair, "admin");

            //Enrollment enr = await caService.Enroll("admin", "adminpw",csr:csr);
            //PrintEnrollmentInstance(enr);
            #endregion Test Enroll with csr

            #region Test enroll with ssl
            //CAService caService = new CAService(null, caEndpoint: "https://localhost:7054", caName: "ca-org1");

            //CAService caService = new CAService(null, caEndpoint: "https://localhost:7054", caName: "ca-org1", caCertsPath: "ca-cert.pem");

            //Enrollment enr = await caService.Enroll("admin", "adminpw");
            //PrintEnrollmentInstance(enr);
            #endregion Test enroll with ssl

            #region Test Wallet
            CAService caService = new CAService(null, caEndpoint: "https://localhost:7054", caName: "ca-org1", caCertsPath: "ca-cert.pem");
            //creating File System Wallet
            Wallet wallet = new Wallet(new FSWalletStore("D:\\CS\\TesisHF\\Repos\\Test15\\walletDir"));

            #region Enroll and save admin data
            //Enrollment enr = await caService.Enroll("admin", "adminpw");
            //X509Identity identity = new X509Identity(enr.Cert, enr.KeyPair, "Org1MSP");
            //wallet.Put("admin", identity);
            #endregion Enroll and save admin data

            #region retrieve admin data
            var adminIdentity = wallet.Get("admin");
            Enrollment enr = new Enrollment(adminIdentity.GetPrivateKey(), adminIdentity.GetCertificate(), null, caService);
            #endregion retrieve admin data

            string secret = await caService.Register("usr4", "", 10, null, enr);

            Enrollment enr2 = await caService.Enroll("usr4", secret);

            X509Identity identity = new X509Identity(enr2.Cert, enr2.KeyPair, "Org1MSP");
            //Console.WriteLine("----------Initial Identity----------");
            //PrintIdentity(identity);
            wallet.Put("usr4", identity);
            //var newIdentity = wallet.Get("usr3");
            //Console.WriteLine();
            //Console.WriteLine("----------Second Identity----------");
            //PrintIdentity(newIdentity);

            #region Remove identity
            wallet.Remove("usr4");
            #endregion Remove identity


            #region get identity list
            var idenList = wallet.List();
            Console.WriteLine("Identity list");
            foreach (var id in idenList) {
                Console.WriteLine(id);
            }
            #endregion get identity list

            #endregion Test Wallet

        }

        static public async Task<string> TestRevocation(string registrarName, string registrarSecret, string userId, string userSecret = "", int maxEnrollment = 10, string caEndpoint = "", string caCertsPath = "") {
            Console.WriteLine("Enter revocation method");
            CAService caService = new CAService(null, caEndpoint: caEndpoint, caName: "ca-org1", caCertsPath: caCertsPath);
            Enrollment enr = await caService.Enroll(registrarName, registrarSecret);
            Console.WriteLine("Admin enrolled");

            string secret = await caService.Register(userId, userSecret, maxEnrollment, null, enr);
            Console.WriteLine("Secret:");
            Console.WriteLine(secret);

            Enrollment enr2 = await caService.Enroll(userId, secret);
            PrintEnrollmentInstance(enr2);
            Console.WriteLine("New user enrolled");

            var result = await caService.Revoke(userId, "", "", "unspecified", true, enr);
            Console.WriteLine("Result revocation:");
            Console.WriteLine("CRL:");
            Console.WriteLine(result);

            return "Ready";
        }

        static public void PrintEnrollmentInstance(Enrollment enr) {
            Console.WriteLine("Enrollment:");
            Console.WriteLine("Cert");
            Console.WriteLine(enr.Cert);
            Console.WriteLine("CAChainCert:");
            Console.WriteLine(enr.CAChainCert);


            Console.WriteLine("Private key:");
            //Console.WriteLine(enr.KeyPair.Private);
            //// extract private key
            if (enr.KeyPair != null) {
                var privateKeyInfo = PrivateKeyInfoFactory.CreatePrivateKeyInfo(enr.KeyPair.Private);
                var privateKeyPem = Convert.ToBase64String(privateKeyInfo.GetDerEncoded());
                privateKeyPem = Regex.Replace(privateKeyPem, ".{64}", "$0\n");
                var strBuilder = new StringBuilder();
                strBuilder.AppendLine($"-----BEGIN PRIVATE KEY-----");
                strBuilder.AppendLine(privateKeyPem);
                strBuilder.AppendLine($"-----END PRIVATE KEY-----");
                privateKeyPem = strBuilder.ToString();
                Console.WriteLine(privateKeyPem);


                Console.WriteLine("Public key:");

                //// extract Public key (PEM)
                var publicKeyInfo = SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(enr.KeyPair.Public);
                var publicKeyPem = Convert.ToBase64String(publicKeyInfo.GetDerEncoded());
                publicKeyPem = Regex.Replace(publicKeyPem, ".{64}", "$0\n");
                strBuilder.Clear();
                strBuilder.AppendLine($"-----BEGIN PUBLIC KEY-----");
                strBuilder.AppendLine(publicKeyPem);
                strBuilder.AppendLine($"-----END PUBLIC KEY-----");
                publicKeyPem = strBuilder.ToString();

                //Console.WriteLine(enr.KeyPair.Public);
                Console.WriteLine(publicKeyPem);
            }
        }

        static public void PrintIdentity(X509Identity ident) {
            Console.WriteLine("Identity:");
            Console.WriteLine("MSP Id");
            Console.WriteLine(ident.GetMspId());
            Console.WriteLine("Certificate:");
            Console.WriteLine(ident.GetCertificate());
            //Console.WriteLine("Key:");
            //Console.WriteLine(ident.GetPrivateKey);
            var kPair = ident.GetPrivateKey();

            Console.WriteLine("Private key:");
            //Console.WriteLine(enr.KeyPair.Private);
            //// extract private key
            if (kPair != null) {
                var privateKeyInfo = PrivateKeyInfoFactory.CreatePrivateKeyInfo(kPair.Private);
                var privateKeyPem = Convert.ToBase64String(privateKeyInfo.GetDerEncoded());
                privateKeyPem = Regex.Replace(privateKeyPem, ".{64}", "$0\n");
                var strBuilder = new StringBuilder();
                strBuilder.AppendLine($"-----BEGIN PRIVATE KEY-----");
                strBuilder.AppendLine(privateKeyPem);
                strBuilder.AppendLine($"-----END PRIVATE KEY-----");
                privateKeyPem = strBuilder.ToString();
                Console.WriteLine(privateKeyPem);


                Console.WriteLine("Public key:");

                //// extract Public key (PEM)
                var publicKeyInfo = SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(kPair.Public);
                var publicKeyPem = Convert.ToBase64String(publicKeyInfo.GetDerEncoded());
                publicKeyPem = Regex.Replace(publicKeyPem, ".{64}", "$0\n");
                strBuilder.Clear();
                strBuilder.AppendLine($"-----BEGIN PUBLIC KEY-----");
                strBuilder.AppendLine(publicKeyPem);
                strBuilder.AppendLine($"-----END PUBLIC KEY-----");
                publicKeyPem = strBuilder.ToString();

                //Console.WriteLine(enr.KeyPair.Public);
                Console.WriteLine(publicKeyPem);
            }
        }

    }
}