using Microsoft.VisualStudio.TestTools.UnitTesting;
using FabricCaClient;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using FabricCaClient.Exceptions;
using System.Security.Principal;
using System.Runtime.CompilerServices;
using FabricCaClient.Crypto;

namespace FabricCaClient.Tests {
    [TestClass()]
    public class CAServiceTests {
        private string caEndpoint = "https://localhost:7054";
        private string caName = "ca-org1";
        private string caCertsPath = "ca-cert.pem";

        private string registrarName = "admin";
        private string registrarSecret = "adminpw";

        CAService caService;
        Enrollment adminEnr;

        int baseUsrId = 30;

        string unauthorizedMessage = "Response status code does not indicate success: 401 (Unauthorized).";

        [TestInitialize]
        public async Task CAServiceTest() {
            // Arrange 
            caService = new CAService(null, caEndpoint: caEndpoint, caName: caName, caCertsPath: caCertsPath);
            adminEnr = await caService.Enroll(registrarName, registrarSecret);
        }

        [TestMethod()]
        [DoNotParallelize]
        public void GetCaNameTest() {
            string result = caService.GetCaName();
            Assert.AreEqual(result, caName, "CaName retrieved does not match expected.");
        }

        [TestMethod()]
        [DoNotParallelize]
        public async Task Enroll_DeniedWhenNotRegisteredTest() {
            // Arrange 
            string userId = "appUser" + (baseUsrId);
            string userSecret = "xsw";
            
            // check user is unable to enroll because is not registered yet
            try {
                // Act
                Enrollment enr = await caService.Enroll(userId, userSecret);
            }
            catch (EnrollmentException exc) {
                // Assert
                StringAssert.Contains(exc.ToString(), unauthorizedMessage);
                return;
            }
            // Assert
            Assert.Fail("Expected a registration denial.");
        }

        [TestMethod()]
        [DoNotParallelize]
        public async Task EnrollAfterRegisterTest() {
            string userId = "appUser" + (baseUsrId + 1);
            string userSecret = "xsw";
            int maxEnrollment = 5;

            // register user
            string secret = await caService.Register(userId, userSecret, maxEnrollment, null, adminEnr);
            // check user is able to enroll after being registered
            Enrollment usrEnr = await caService.Enroll(userId, secret);
        }

        [TestMethod()]
        [DoNotParallelize]
        public async Task ReenrollTest() {
            string userId = "appUser" + (baseUsrId + 2);
            string userSecret = "xsw";
            int maxEnrollment = 5;
            
            // register user
            string secret = await caService.Register(userId, userSecret, maxEnrollment, null, adminEnr);
            
            //enroll
            Enrollment usrEnr = await caService.Enroll(userId, secret);

            // check user is able to reenroll with given credentials
            Enrollment usrReenr = await caService.Reenroll(usrEnr);
        }

        [TestMethod()]
        [DoNotParallelize]
        public async Task RevokeTest() {
            string userId = "appUser" + (baseUsrId + 3);
            string userSecret = "xsw";
            int maxEnrollment = 5;

            // register user
            string secret = await caService.Register(userId, userSecret, maxEnrollment, null, adminEnr);

            // enroll user
            Enrollment usrEnr = await caService.Enroll(userId, secret);

            // revoke credentials
            var result = await caService.Revoke(userId, "", "", "unspecified", true, adminEnr);

            try {
                // check user is unable to enroll after its credentials are revoked
                Enrollment newUsrEnr = await caService.Enroll(userId, secret);
            }
            catch (EnrollmentException exc) {
                StringAssert.Contains(exc.ToString(), unauthorizedMessage);
                return;
            }

            Assert.Fail("Expected an enrollment denial.");
        }

        [TestMethod()]
        [DoNotParallelize]
        public async Task RegisterWithSecretProvidedTest() {
            string userId = "appUser" + (baseUsrId + 4);
            string usrpw = userId + "pw";
            int maxEnrollment = 5;

            string secret = await caService.Register(userId, usrpw, maxEnrollment, null, adminEnr);
            Assert.AreEqual(secret, usrpw, "Registration call didn't set provided secret.");
        }

        [TestMethod()]
        [DoNotParallelize]
        public async Task EnrollWithCSRTest() {
            var cryptoPrimitives = new CryptoPrimitives();
            var keyPair = cryptoPrimitives.GenerateKeyPair();
            var csr = cryptoPrimitives.GenerateCSR(keyPair, "admin");

            // provide csr 
            Enrollment enr = await caService.Enroll("admin", "adminpw", csr: csr);
        }
    }
}