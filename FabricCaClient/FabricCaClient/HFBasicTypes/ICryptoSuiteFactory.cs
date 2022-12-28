namespace FabricCaClient.HFBasicTypes {
    internal interface ICryptoSuiteFactory {
        /// <summary>
        /// Produces a Crypto Suite with no specifications.
        /// </summary>
        /// <returns> A default crypto suite. </returns>
        ICryptoSuite GetCryptoSuite();
    }
}