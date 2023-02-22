using Microsoft.VisualStudio.TestTools.UnitTesting;
using FabricNetwork.Wallets;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using FabricCaClient;
using FabricCaClient.Exceptions;
using FabricNetwork.Identities;

namespace FabricNetwork.Wallets.Tests {
    [TestClass()]
    public class WalletTests {
        private string caEndpoint = "https://localhost:7054";
        private string caName = "ca-org1";
        private string caCertsPath = "ca-cert.pem";

        private string registrarName = "admin";
        private string registrarSecret = "adminpw";
        private string orgMSP = "adminpw";

        private string storagePath = "D:\\CS\\TesisHF\\Repos\\Test15\\walletDir";

        CAService caService;
        Enrollment adminEnr;
        Wallet wallet;

        int baseUsrId = 20;

        string unauthorizedMessage = "Response status code does not indicate success: 401 (Unauthorized).";

        [TestInitialize]
        public async Task WalletTest() {
            // Arrange 
            caService = new CAService(null, caEndpoint: caEndpoint, caName: caName, caCertsPath: caCertsPath);
            adminEnr = await caService.Enroll(registrarName, registrarSecret);
            //creating File System Wallet
            wallet = new Wallet(new FSWalletStore(storagePath));
        }

        [TestMethod()]
        [DoNotParallelize]
        public void GetTest() {
            FSWalletStore.ClearDirectory(storagePath);

            var idenList = wallet.List();
            Assert.AreEqual(idenList.Length, 0, "Initially a wallet should contain no values.");

            //put element in wallet
            X509Identity identity = new X509Identity(adminEnr.Cert, adminEnr.PrivateKey, orgMSP);
            wallet.Put(registrarName, identity);

            // retrieve identity
            var retrievedIdentity = wallet.Get(registrarName);
            Assert.AreEqual(identity.GetCertificate(), retrievedIdentity.GetCertificate(), "Identity retrieved from wallet doesn't match values provided initially.");

            // clear wallet
            wallet.Remove(registrarName);
        }

        [TestMethod()]
        [DoNotParallelize]
        public void PutTest() {
            FSWalletStore.ClearDirectory(storagePath);

            var idenList = wallet.List();
            Assert.AreEqual(idenList.Length, 0, "Initially a wallet should contain no values.");
            
            //put element in wallet
            X509Identity identity = new X509Identity(adminEnr.Cert, adminEnr.PrivateKey, orgMSP);
            wallet.Put(registrarName, identity);

            // check element was saved
            var newIdenList = wallet.List();
            Assert.AreEqual(newIdenList.Length, 1, "Wallet should contain just the element saved.");
            Assert.AreEqual(newIdenList[0], registrarName, "Wallet content doesn't match the expected file.");

            // clear wallet
            wallet.Remove(registrarName);
        }

        [TestMethod()]
        [DoNotParallelize]
        public void RemoveTest() {
            FSWalletStore.ClearDirectory(storagePath);

            var idenList = wallet.List();
            Assert.AreEqual(idenList.Length, 0, "Initially a wallet should contain no values.");

            //put element in wallet
            X509Identity identity = new X509Identity(adminEnr.Cert, adminEnr.PrivateKey, orgMSP);
            wallet.Put(registrarName, identity);

            // check element was saved
            var newIdenList = wallet.List();
            Assert.AreEqual(newIdenList.Length, 1, "Wallet should contain just the element saved.");
            Assert.AreEqual(newIdenList[0], registrarName, "Wallet content doesn't match the expected file.");

            // clear wallet
            wallet.Remove(registrarName);

            // check wallet is empty again
            newIdenList = wallet.List();
            Assert.AreEqual(newIdenList.Length, 0, "Remove operation invalid, expected an empty wallet.");
        }

        [TestMethod()]
        [DoNotParallelize]
        public void ListTest() {
            FSWalletStore.ClearDirectory(storagePath);

            var idenList = wallet.List();
            Assert.AreEqual(idenList.Length, 0, "Initially a wallet should contain no values.");
        }

        #region to test later

        // load enrollment from wallet and test complete flow again.
        #endregion to test later
        [TestMethod()]
        [DoNotParallelize]
        public async Task CaClientFlowWithWalletTest() {
            string userId = "appUser" + (baseUsrId + 1);
            string userSecret = "xsw";
            int maxEnrollment = 5;

            FSWalletStore.ClearDirectory(storagePath);

            X509Identity identity = new X509Identity(adminEnr.Cert, adminEnr.PrivateKey, orgMSP);
            wallet.Put(registrarName, identity);

            // retrieve identity
            var adminIdentity = wallet.Get(registrarName);
            Enrollment newAdminEnr = new Enrollment(adminIdentity.GetPrivateKey(), adminIdentity.GetCertificate(), null, caService);

            // register user
            string secret = await caService.Register(userId, userSecret, maxEnrollment, null, newAdminEnr);

            // enroll user
            Enrollment usrEnr = await caService.Enroll(userId, secret);

            // revoke credentials
            var result = await caService.Revoke(userId, "", "", "unspecified", true, newAdminEnr);

            try {
                // check user is unable to enroll after its credentials are revoked
                Enrollment newUsrEnr = await caService.Enroll(userId, secret);
                wallet.Remove(registrarName);
            }
            catch (EnrollmentException exc) {
                StringAssert.Contains(exc.ToString(), unauthorizedMessage);
                wallet.Remove(registrarName);
                return;
            }

            Assert.Fail("Expected an enrollment denial.");
        }
    }
}