using FabricCaClient;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.X509;
using System.Text;
using System.Text.RegularExpressions;

namespace TestSdkCSharp {
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

            var con = await TestRevocation("admin", "adminpw", "appUser70", "");
            Console.WriteLine("Exit revocation method");
            Console.WriteLine(con);
            #endregion Test Revoke
        }

        static public async Task<string> TestRevocation(string registrarName, string registrarSecret, string userId, string userSecret = "", int maxEnrollment = 10) {
            Console.WriteLine("Enter revocation method");
            CAService caService = new CAService(null, caName: "ca-org1");
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
}