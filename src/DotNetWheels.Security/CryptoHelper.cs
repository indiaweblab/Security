using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using DotNetWheels.Core;

namespace DotNetWheels.Security
{
    public static class CryptoHelper
    {
        private static IOneWayHash _onewayhash;
        private static IAESProvider _aesprovider;

        static CryptoHelper()
        {
            _onewayhash = new OneWayHash();
            _aesprovider = new AESProvider();
        }

        public static XResult<String> GetMD5(String input)
        {
            return _onewayhash.GetMD5(input);
        }

        public static XResult<String> GetSHA1(String input, SHA1HashSize size = SHA1HashSize.SHA160)
        {
            return _onewayhash.GetSHA1(input, size);
        }

        public static XResult<String> Encrypt(String input, String key)
        {
            if (String.IsNullOrEmpty(input))
            {
                throw new ArgumentNullException("The input value is null");
            }

            if (String.IsNullOrEmpty(key))
            {
                throw new ArgumentNullException("The key is null");
            }

            try
            {
                return _aesprovider.Encrypt(input, new KeyManager(key));
            }
            catch (Exception)
            {
                return null;
            }
        }

        public static XResult<String> Decrypt(String encryptedString, String key)
        {
            if (String.IsNullOrEmpty(encryptedString))
            {
                throw new ArgumentNullException("The encrypted value is null");
            }

            if (String.IsNullOrEmpty(key))
            {
                throw new ArgumentNullException("The key is null");
            }

            try
            {
                return _aesprovider.Decrypt(encryptedString, new KeyManager(key));
            }
            catch (Exception)
            {
                return null;
            }
        }

        public static XResult<Byte[]> Encrypt(Stream stream, String key)
        {
            if (stream == null)
            {
                throw new ArgumentNullException("The stream is null");
            }

            if (String.IsNullOrEmpty(key))
            {
                throw new ArgumentNullException("The key is null");
            }

            try
            {
                return _aesprovider.Encrypt(stream, new KeyManager(key));
            }
            catch (Exception)
            {
                return null;
            }
        }

        public static XResult<Byte[]> Decrypt(Byte[] encryptedData, String key)
        {
            if (encryptedData == null || encryptedData.Length == 0)
            {
                throw new ArgumentNullException("The encrypted value is null");
            }

            if (String.IsNullOrEmpty(key))
            {
                throw new ArgumentNullException("The key is null");
            }

            try
            {
                return _aesprovider.Decrypt(encryptedData, new KeyManager(key));
            }
            catch (Exception)
            {
                return null;
            }
        }

        public static XResult<Byte[]> Decrypt(Stream stream, String key)
        {
            if (stream == null || stream.Length == 0)
            {
                throw new ArgumentNullException("The stream is null");
            }

            if (String.IsNullOrEmpty(key))
            {
                throw new ArgumentNullException("The key is null or empty");
            }

            try
            {
                return _aesprovider.Decrypt(stream, new KeyManager(key));
            }
            catch (Exception)
            {
                return null;
            }
        }

    }
}
