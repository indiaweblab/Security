using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace DotNetWheels.Security
{

    public sealed class KeyManager
    {
        private static IOneWayHash _hash = new OneWayHash();
        private Rfc2898DeriveBytes _rfcKey;

        public Byte[] Key { get; private set; }

        public KeyManager(String key)
        {
            if (key == null || key.Length == 0)
            {
                throw new ArgumentNullException("key");
            }

            Byte[] salt = Encoding.ASCII.GetBytes(_hash.GetSHA1(key, SHA1HashSize.SHA512));
            _rfcKey = new Rfc2898DeriveBytes(key, salt);
        }

        public void GenerateKey(Int32 keySize)
        {
            this.Key = _rfcKey.GetBytes(keySize / 8);
        }

    }
}
