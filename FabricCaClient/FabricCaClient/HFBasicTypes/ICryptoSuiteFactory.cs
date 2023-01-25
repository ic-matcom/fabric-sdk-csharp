namespace FabricCaClient.HFBasicTypes {
    /// <summary>
    /// Factory to produce a set of crypto suite implementations with different cryptographic algorithms and strengths.
    /// </summary>
    public interface ICryptoSuiteFactory {
        //String DEFAULT_JDK_PROVIDER = "org.hyperledger.fabric.sdk.security.default_jdk_provider"; change to a class member

        /// <summary>
        /// Produces a crypto suite according to specified properties.
        /// </summary>
        /// <param name="properties"></param>
        /// <returns></returns>
        ICryptoSuite GetCryptoSuite(Properties properties);

        /// <summary>
        /// Produces a Crypto Suite with no specifications.
        /// </summary>
        /// <returns> A default crypto suite. </returns>
        ICryptoSuite GetCryptoSuite();

        /// <summary>
        /// Returns the default Crypto Suite Factory implementation.
        /// </summary>
        /// <returns>A single instance of Crypto Suite</returns>
        static ICryptoSuiteFactory getDefault() {
            return HLSDKCSCryptoSuiteFactory.getDefault();
        }
    }
}