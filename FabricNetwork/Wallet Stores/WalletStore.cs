using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;


namespace FabricNetwork {
    public interface WalletStore {
        /// <summary>
        /// Gets data from the wallet storage.
        /// </summary>
        /// <param name="label">Label used to identify the data required within the wallet.</param>
        /// <returns></returns>
        string Get(string label);

        /// <summary>
        /// Puts data in the wallet.
        /// </summary>
        /// <param name="label">Label used to identify the data within the wallet.</param>
        /// <param name="identity">Data to store in the wallet.</param>
        void Put(string label, string data);

        /// <summary>
        /// Removes an identity from the wallet.
        /// </summary>
        /// <param name="label">Label used to identify the data to remove within the wallet.</param>
        void Remove(string label);

        /// <summary>
        /// Returns the labels of all instances saved in the wallet.
        /// </summary>
        /// <returns>A string list containing the labels.</returns>
        string[] List();
    }
}
