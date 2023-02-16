using Newtonsoft.Json.Linq;
using System.Security.Principal;
using System.Text.Json.Nodes;
using System.Text;
using Newtonsoft.Json;
using FabricNetwork.Identities;

namespace FabricNetwork.Wallets
{
    public class Wallet
    {
        private WalletStore _walletStore;

        public Wallet(WalletStore walletStore)
        {
            _walletStore = walletStore;
        }

        public X509Identity Get(string label)
        {
            string identityString = _walletStore.Get(label);
            string decodedIden = Encoding.UTF8.GetString(Convert.FromBase64String(identityString));
            return X509Identity.FromJson(JObject.Parse(decodedIden));
        }

        public void Put(string label, Identity identity)
        {
            JObject jsonIdentity = identity.ToJson();
            string identityString = jsonIdentity.ToString(Formatting.None);
            _walletStore.Put(label, Convert.ToBase64String(Encoding.UTF8.GetBytes(identityString)));
        }

        public void Remove(string label)
        {
            _walletStore.Remove(label);
        }

        public string[] List()
        {
            return _walletStore.List();
        }
    }
}