using Newtonsoft.Json.Linq;
using System.Security.Principal;
using System.Text.Json.Nodes;
using System.Text;
using Newtonsoft.Json;
using FabricNetwork.Identities;
using Microsoft.VisualBasic;

namespace FabricNetwork.Wallets
{
    /// <summary>
    /// A class to safe identity information. The wallet is backed by a store that handles
    /// persistence of data. Different types of walletStores can be used such as in-memory, file system or data-based.
    /// </summary>
    public class Wallet
    {
        private WalletStore _walletStore;

        /// <summary>
        /// Creates a wallet instance backed by a given store. This can be used to create a wallet using any custom store implementation.
        /// </summary>
        /// <param name="walletStore">Wallet store to use for data persistence.</param>
        public Wallet(WalletStore walletStore)
        {
            _walletStore = walletStore;
        }

        /// <summary>
        /// Gets an identity from the wallet.
        /// </summary>
        /// <param name="label">Label used to identify the identity within the wallet.</param>
        /// <returns>An instance of the identity saved with the given label.</returns>
        public X509Identity Get(string label)
        {
            string identityString = _walletStore.Get(label);
            string decodedIden = Encoding.UTF8.GetString(Convert.FromBase64String(identityString));
            return X509Identity.FromJson(JObject.Parse(decodedIden));
        }

        /// <summary>
        /// Puts an identity in the wallet.
        /// </summary>
        /// <param name="label">Label used to identify the identity within the wallet.</param>
        /// <param name="identity">Identity to store in the wallet.</param>
        public void Put(string label, Identity identity)
        {
            JObject jsonIdentity = identity.ToJson();
            string identityString = jsonIdentity.ToString(Formatting.None);
            _walletStore.Put(label, Convert.ToBase64String(Encoding.UTF8.GetBytes(identityString)));
        }

        /// <summary>
        /// Removes an identity from the wallet.
        /// </summary>
        /// <param name="label">Label used to identify the identity within the wallet.</param>
        public void Remove(string label)
        {
            _walletStore.Remove(label);
        }

        /// <summary>
        /// Returns the labels of all identities in the wallet.
        /// </summary>
        /// <returns>A string list containing identities labels.</returns>
        public string[] List()
        {
            return _walletStore.List();
        }
    }
}