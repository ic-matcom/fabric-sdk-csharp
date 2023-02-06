using FabricCaClient;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Encodings;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;
using System.Collections;
using System.Reflection.PortableExecutable;
using System.Text;
using System.Text.RegularExpressions;

namespace TestSdkCSharp {
    internal class Program {
        static async Task Main(string[] args) {
            //CAClient caclient = new CAClient();
            //Console.WriteLine("Intialized");
            //var jsonResponse = await caclient.GetCaInfo();
            //Console.WriteLine($"{jsonResponse}\n");

            CAService caService = new CAService(null);
            Console.WriteLine("Initilized entity");
            //var jsonResponse = await caService.GetCaInfo();
            //Console.WriteLine($"{jsonResponse}\n");
            // catch exception when server ir not up
            //No connection could be made because the target machine actively refused it.                                              

            #region Test Enroll
            Enrollment enr = await caService.Enroll("admin", "adminpw");
            //PrintEnrollment(enr);
            #endregion Test Enroll

            #region Test Reenroll
            Enrollment reenroll = await caService.Reenroll(enr);
            PrintEnrollmentInstance(reenroll);

            #endregion Test reenroll
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