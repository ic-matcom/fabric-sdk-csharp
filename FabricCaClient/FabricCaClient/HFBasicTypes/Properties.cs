using System.Collections;
using System.Diagnostics.CodeAnalysis;

namespace FabricCaClient.HFBasicTypes
{
    public class Properties : IDictionary<string, string> {
        public string this[string key] { get => throw new NotImplementedException(); set => throw new NotImplementedException(); }

        public ICollection<string> Keys => throw new NotImplementedException();

        public ICollection<string> Values => throw new NotImplementedException();

        public int Count => throw new NotImplementedException();

        public bool IsReadOnly => throw new NotImplementedException();

        public void Add(string key, string value) {
            throw new NotImplementedException();
        }

        public void Add(KeyValuePair<string, string> item) {
            throw new NotImplementedException();
        }

        public void Clear() {
            throw new NotImplementedException();
        }

        public bool Contains(KeyValuePair<string, string> item) {
            throw new NotImplementedException();
        }

        public bool ContainsKey(string key) {
            throw new NotImplementedException();
        }

        public void CopyTo(KeyValuePair<string, string>[] array, int arrayIndex) {
            throw new NotImplementedException();
        }

        public IEnumerator<KeyValuePair<string, string>> GetEnumerator() {
            throw new NotImplementedException();
        }

        public bool Remove(string key) {
            throw new NotImplementedException();
        }

        public bool Remove(KeyValuePair<string, string> item) {
            throw new NotImplementedException();
        }

        public bool TryGetValue(string key, [MaybeNullWhen(false)] out string value) {
            throw new NotImplementedException();
        }

        internal void Set(object sECURITY_LEVEL, object value) {
            throw new NotImplementedException();
        }

        IEnumerator IEnumerable.GetEnumerator() {
            throw new NotImplementedException();
        }
    }
}