namespace FabricCaClient.HFBasicTypes {
    /// <summary>
    /// Factory to produce a set of crypto suite implementations with different cryptographic algorithms and strengths.
    /// </summary>
    public interface ICryptoSuiteFactory {
        /// <summary>
        /// Produces a Crypto Suite with no specifications.
        /// </summary>
        /// <returns> A default crypto suite. </returns>
        ICryptoSuite GetCryptoSuite();
    }
}