using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using DotNetWheels.Core;

namespace DotNetWheels.Security
{
    public sealed class KeyManager
    {
        private static IOneWayHash _hash = new OneWayHash();
        private Rfc2898DeriveBytes _rfcKey;
        private Exception _innerException;

        public Byte[] Key { get; private set; }

        public KeyManager(String key)
        {
            if (key == null || key.Length == 0)
            {
                _innerException = new ArgumentNullException("key");
                return;
            }

            var sha1Result = _hash.GetSHA1(key, SHA1HashSize.SHA512);
            if (sha1Result.Success)
            {
                Byte[] salt = Encoding.ASCII.GetBytes(sha1Result.Value);
                _rfcKey = new Rfc2898DeriveBytes(key, salt);
            }
            else
            {
                _innerException = sha1Result.Exceptions[0];
            }
        }

        public XResult<Boolean> GenerateKey(Int32 keySize)
        {
            if (_innerException != null)
            {
                return new XResult<Boolean>(false, _innerException);
            }

            if (_rfcKey == null)
            {
                return new XResult<Boolean>(false, new ArgumentNullException("_rfcKey"));
            }

            this.Key = _rfcKey.GetBytes(keySize / 8);
            return new XResult<Boolean>(true);
        }

    }
}
