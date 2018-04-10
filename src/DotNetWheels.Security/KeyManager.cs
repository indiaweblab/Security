using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace DotNetWheels.Security
{

    public sealed class KeyManager
    {
        private Byte[] _key;
        private Byte[] _iv;

        private Byte[] _bkey;
        private Byte[] _biv;

        public Byte[] IV
        {
            get { return _iv; }
        }

        public Byte[] Key
        {
            get { return _key; }
        }

        public KeyManager(String key)
        {
            if (key == null || key.Length == 0)
            {
                throw new ArgumentNullException("key");
            }

            var onewayHash = new OneWayHash();

            String md5Key = onewayHash.GetMD5(key);

            _bkey = Encoding.UTF8.GetBytes(md5Key);

            String md5IV = onewayHash.GetMD5(md5Key);
            DestroyManagedString(md5Key);

            _biv = Encoding.UTF8.GetBytes(md5IV);
            DestroyManagedString(md5IV);

        }

        public void GenerateKeyAndIV(Int32 keySize, Int32 blockSize)
        {
            _key = new Byte[keySize / 8];
            for (var i = 0; i < _key.Length; i++)
            {
                _key[i] = _bkey[i];
            }

            DestoryManagedBytes(_bkey);

            _iv = new Byte[blockSize / 8];
            for (var i = 0; i < _iv.Length; i++)
            {
                _iv[i] = _biv[i];
            }

            DestoryManagedBytes(_biv);
        }

        public void DestoryManagedBytes(Byte[] bytes)
        {
            if (bytes == null) { return; }
            Int32 len = bytes.Length;
            unsafe
            {
                fixed (byte* b = bytes)
                {
                    for (int i = 0; i < len; i++)
                    {
                        b[i] = 0;
                    }
                }
            }
        }

        public void DestroyManagedString(String value)
        {
            if (value == null || value.Length == 0) { return; }
            unsafe
            {
                fixed (char* s = value)
                {
                    for (int i = 0; i < value.Length; i++)
                    {
                        s[i] = '\0';
                    }
                }
            }
        }

    }
}
