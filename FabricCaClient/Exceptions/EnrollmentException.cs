using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace FabricCaClient.Exceptions {
    [Serializable]
    public class EnrollmentException : Exception {
        public EnrollmentException() { }

        public EnrollmentException(string message) : base(message) { }

        public EnrollmentException(string message, Exception inner) : base(message, inner) { }
    }
}
