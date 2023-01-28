using System.Collections;
using System.Diagnostics.CodeAnalysis;
using System.Globalization;

namespace FabricCaClient.HFBasicTypes {
    /// <summary>
    /// Represents a persistent set of properties.
    /// </summary>
    public class Properties : IDictionary<string, string> {
        //Note in java is java.util.Dictionary<K,V>: Hashtable<Object,Object>
        private string sourceFile;
        private Dictionary<string, string> list = new Dictionary<string, string>(StringComparer.InvariantCultureIgnoreCase);

        public string this[string key] { get => Get(key); set => Set(key, value); }

        public ICollection<string> Keys => list.Keys;

        public ICollection<string> Values => list.Values;

        public int Count => list.Count;

        public bool IsReadOnly => false;

        public void Add(string key, string value) {
            throw new NotImplementedException();
        }

        public void Add(KeyValuePair<string, string> item) {
            Set(item.Key, item.Value);
        }

        public void Clear() {
            list.Clear();
        }

        public bool Contains(KeyValuePair<string, string> property) {
            return list.Contains(property);

        }

        public bool ContainsKey(string key) {
            return list.ContainsKey(key);
        }

        public void CopyTo(KeyValuePair<string, string>[] array, int arrayIndex) {
            throw new NotImplementedException();
        }

        public IEnumerator<KeyValuePair<string, string>> GetEnumerator() {
            foreach (KeyValuePair<string, string> property in list)
                yield return property;
        }

        public bool Remove(string key) {
            return list.Remove(key);
        }

        public bool Remove(KeyValuePair<string, string> property) {
            return list.Remove(property.Key);
        }

        public bool TryGetValue(string key, [MaybeNullWhen(false)] out string value) {
            throw new NotImplementedException();
        }

        /// <summary>
        /// Add a key value pair of properties or modify an existing one.
        /// </summary>
        /// <param name="key">Property name to add</param>
        /// <param name="value">Property value to assign to key</param>
        internal void Set(string key, object value) {
            string finalValue = null;
            if (value != null)
                finalValue = Convert.ToString(value, CultureInfo.InvariantCulture);
            if (!list.ContainsKey(key))
                list.Add(key, finalValue);
            else
                list[key] = finalValue;
        }

        IEnumerator IEnumerable.GetEnumerator() {
            return GetEnumerator();
        }

        public string Get(string key, string value) {
            return Get(key) ?? value;
        }

        public string GetAndRemove(string key) {
            if (list.ContainsKey(key)) {
                string value = list[key];
                list.Remove(key);
                return value;
            }

            return null;
        }

        public string Get(string key) {
            return list.ContainsKey(key) ? list[key] : null;
        }
        public void Save() {
            Save(sourceFile);
        }

        public void Save(string srcFile) {
            sourceFile = srcFile;

            StreamWriter file = new StreamWriter(sourceFile);

            foreach (string key in list.Keys.ToArray())
                if (!string.IsNullOrWhiteSpace(list[key]))
                    file.WriteLine(key + "=" + list[key]);

            file.Close();
        }

        public void Reload() {
            if (!string.IsNullOrEmpty(sourceFile))
                Load(sourceFile);
        }

        public void Load(string srcFile) {
            sourceFile = srcFile;
            list = new Dictionary<string, string>(StringComparer.InvariantCultureIgnoreCase);

            if (File.Exists(sourceFile))
                foreach (string line in File.ReadAllLines(sourceFile)) {
                    if (!string.IsNullOrEmpty(line) && !line.StartsWith(";") && !line.StartsWith("#") && !line.StartsWith("'") && line.Contains('=')) {
                        int index = line.IndexOf('=');
                        string key = line[..index].Trim();
                        string value = line[(index + 1)..].Trim();

                        if (value.StartsWith("\"") && value.EndsWith("\"") || value.StartsWith("'") && value.EndsWith("'")) {
                            value = value[1..^1];
                        }

                        list[key] = value;
                    }
                }
        }

        public Properties Clone() {
            Properties properties = new Properties {
                sourceFile = sourceFile,
                list = list.ToDictionary(a => a.Key, a => a.Value)
            };
            return properties;
        }
    }
}