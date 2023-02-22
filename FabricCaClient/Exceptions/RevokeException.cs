using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace FabricCaClient.Exceptions {
    [Serializable]
    public class RevokeException : Exception {
        public RevokeException() { }

        public RevokeException(string message) : base(message) { }

        public RevokeException(string message, Exception inner) : base(message, inner) { }
    }
}
