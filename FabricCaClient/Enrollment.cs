namespace FabricCaClient {
    public class Enrollment {
        private string privateKey;
        private string item1;
        private string item2;
        private CAService cAService;

        public Enrollment(string privateKey, string item1, string item2, CAService cAService) {
            this.privateKey = privateKey;
            this.item1 = item1;
            this.item2 = item2;
            this.cAService = cAService;
        }

        public string Cert { get; internal set; }
    }
}