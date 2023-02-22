using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.IO;
using System.Collections;

namespace FabricNetwork.Wallets {
    /// <summary>
    /// A <see cref="WalletStore"/> that safes info at the file system directory.
    /// </summary>
    public class FSWalletStore : WalletStore {
        /// <summary>
        /// Path use to safe info.
        /// </summary>
        public string StorePath;

        /// <summary>
        /// Sufix to use for files generated.
        /// </summary>
        private const string idFileSuffix = ".id";

        /// <summary>
        /// Inititalizes a store backed by the provided file system directory.
        /// </summary>
        /// <param name="directory">Path to use for wallet storage.</param>
        public FSWalletStore(string directory) {
            // create directory
            Directory.CreateDirectory(directory);
            // safe path to store identities
            StorePath = directory;
        }

        /// <summary>
        /// Gets data from the wallet storage.
        /// </summary>
        /// <param name="label">Label used to identify the data required within the wallet.</param>
        /// <returns>A string with the data saved under the given label.</returns>
        /// <exception cref="Exception"></exception>
        public string Get(string label) {
            string identityPath = GetFilePath(label);

            try {
                return File.ReadAllText(identityPath);
            }
            catch (Exception exc) {
                throw new Exception("Unable to retrieve identity data from store.", exc);
            }
        }

        /// <summary>
        /// Returns the labels of all instances saved in the wallet.
        /// </summary>
        /// <returns>A string list containing the labels.</returns>
        /// <exception cref="Exception"></exception>
        public string[] List() {
            try {
                string[] idList = Directory.GetFiles(StorePath, "*" + idFileSuffix);

                // Leaving the list in just identitie's label
                for (int i = 0; i < idList.Length; i++) {
                    idList[i] = idList[i].Substring(StorePath.Length + 1, idList[i].Length - idFileSuffix.Length - StorePath.Length - 1);
                }

                return idList;
            }
            catch (Exception exc) {
                throw new Exception("Unable to retrieve identities data from store.", exc);
            }
        }

        /// <summary>
        /// Puts data in the wallet.
        /// </summary>
        /// <param name="label">Label used to identify the data within the wallet.</param>
        /// <param name="data">Data to store in the wallet.</param>
        /// <exception cref="Exception"></exception>
        public void Put(string label, string data) {
            string identityPath = GetFilePath(label);

            try {
                File.WriteAllText(identityPath, data);
            }
            catch (Exception exc) {
                throw new Exception("Unable to save identity data in store.", exc);
            }
        }

        /// <summary>
        /// Removes data from the wallet.
        /// </summary>
        /// <param name="label">Label to identify the data to remove within the wallet.</param>
        /// <exception cref="Exception"></exception>
        public void Remove(string label) {
            string identityPath = GetFilePath(label);

            try {
                File.Delete(identityPath);
            }
            catch (Exception exc) {
                throw new Exception("Unable to remove identity data from store.", exc);
            }
        }

        /// <summary>
        /// Combines the base storage path with the given label and the suffix used at the wallet.
        /// </summary>
        /// <param name="label">Label to add to path.</param>
        /// <returns>The combined path.</returns>
        private string GetFilePath(string label) {
            return Path.Combine(StorePath, label + idFileSuffix);
        }

        /// <summary>
        /// Clears a given directory, removes all files and dirs contained withing it.
        /// </summary>
        /// <param name="path">Path of directory to clear.</param>
        /// <exception cref="Exception"></exception>
        public static void ClearDirectory(string path) {
            DirectoryInfo di = new DirectoryInfo(path);

            foreach (FileInfo file in di.EnumerateFiles()) {
                file.Delete();
            }

            foreach (DirectoryInfo dir in di.EnumerateDirectories()) {
                dir.Delete(true);
            }
        }
    }
}
