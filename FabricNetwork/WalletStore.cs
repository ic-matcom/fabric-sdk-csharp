using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;


namespace FabricNetwork {
    public interface WalletStore {
        string Get(string label);
        void Put(string label, string identity);
        void Remove(string label);
        string[] List();
    }
}
