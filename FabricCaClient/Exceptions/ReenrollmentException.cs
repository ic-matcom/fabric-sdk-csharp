using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace FabricCaClient.Exceptions {
    [Serializable]
    internal class ReenrollmentException : Exception {
        public ReenrollmentException() { }

        public ReenrollmentException(string message) : base(message) { }

        public ReenrollmentException(string message, Exception inner) : base(message, inner) { }
    }
}
