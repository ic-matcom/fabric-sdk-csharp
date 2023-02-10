using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace FabricCaClient.Exceptions {
    [Serializable]
    internal class RegisterException : Exception {
        public RegisterException() { }

        public RegisterException(string message) : base(message) { }

        public RegisterException(string message, Exception inner) : base(message, inner) { }
    }
}
