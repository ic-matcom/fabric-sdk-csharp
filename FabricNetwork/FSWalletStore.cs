using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.IO;
using System.Collections;

namespace FabricNetwork {
    public class FSWalletStore : WalletStore {
        public string StorePath;
        private const string idFileSuffix = ".id";

        public FSWalletStore(string directory) {
            // create directory
            Directory.CreateDirectory(directory);
            // safe path to store identities
            StorePath = directory;
        }

        public string Get(string label) {
            string identityPath = GetFilePath(label);

            try {
                return File.ReadAllText(identityPath);
            }
            catch (Exception exc) {
                throw new Exception("Unable to retrieve identity data from store.", exc);
            }
        }

        public string[] List() {
            try {
                string[] idList = Directory.GetFiles(StorePath, "*" + idFileSuffix);

                // Leaving the list in just identitie's label
                for (int i = 0; i < idList.Length; i++) {
                    idList[i] = idList[i].Substring(StorePath.Length + 1, (idList[i].Length - idFileSuffix.Length) - StorePath.Length - 1);
                }

                return idList;
            }
            catch (Exception exc) {
                throw new Exception("Unable to retrieve identities data from store.", exc);
            }
        }

        public void Put(string label, string identityData) {
            string identityPath = GetFilePath(label);
            
            try {
                File.WriteAllText(identityPath, identityData);
            }
            catch (Exception exc) {
                throw new Exception("Unable to save identity data in store.", exc);
            }
        }

        public void Remove(string label) {
            string identityPath = GetFilePath(label);

            try {
                File.Delete(identityPath);
            }
            catch (Exception exc) {
                throw new Exception("Unable to remove identity data from store.", exc);
            }
        }

        private string GetFilePath(string label) {
            return Path.Combine(StorePath, label + idFileSuffix); 
        }
    }
}
