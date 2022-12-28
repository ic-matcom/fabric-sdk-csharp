namespace FabricCaClient.HFBasicTypes {
    internal class Factory {

        private static ICryptoSuiteFactory _instance;

        private Factory() { }

        /// <summary>
        ///  Returns _instance if != null. Otherwise sets it with a new value and returns it
        /// </summary>
        public static ICryptoSuiteFactory Instance => _instance ??= new HLSDKCSCryptoSuiteFactory();
        //this setting can be done in the ctr.Is it a problem of space?
        //Is it necessary the empty ctr to avoid initializing this object from the beguining?
        //Consider changing this.

        internal static ICryptoSuite GetCryptoSuite() {
            return Instance.GetCryptoSuite();
        }
    }
}