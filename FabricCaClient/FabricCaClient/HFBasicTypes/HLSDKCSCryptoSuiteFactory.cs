using System.Collections.Concurrent;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;

namespace FabricCaClient.HFBasicTypes {
    internal class HLSDKCSCryptoSuiteFactory : ICryptoSuiteFactory {
        private static readonly ConcurrentDictionary<Properties, ICryptoSuite> cache = new ConcurrentDictionary<Properties, ICryptoSuite>();
        private readonly string HASH_ALGORITHM = Config.Instance.GetHashAlgorithm();
        private readonly int SECURITY_LEVEL = Config.Instance.GetSecurityLevel();


        public ICryptoSuite GetCryptoSuite() {
            Properties properties = new Properties();
            properties.Set(Config.SECURITY_LEVEL, SECURITY_LEVEL.ToString());
            properties.Set(Config.HASH_ALGORITHM, HASH_ALGORITHM);

            return GetCryptoSuite(properties);
        }

        private ICryptoSuite GetCryptoSuite(Properties properties) {
            ICryptoSuite ret = null;
            foreach (Properties st in cache.Keys) {
                bool found = true;
                foreach (string key in properties.Keys) {
                    if (!st.Contains(key)) {
                        found = false;
                        break;
                    }
                    else {
                        if (st[key] != properties[key]) {
                            found = false;
                            break;
                        }
                    }
                }
                if (found) {
                    ret = cache[st];
                    break;
                }
            }

            if (ret == null) {
                try {
                    CryptoPrimitives cp = new CryptoPrimitives();
                    cp.SetProperties(properties);
                    cp.Init();
                    ret = cp;
                }
                catch (Exception exc) {
                    throw new Exception(exc.Message, exc);
                }

                cache[properties] = ret;
            }

            return ret;
        }
    }
}