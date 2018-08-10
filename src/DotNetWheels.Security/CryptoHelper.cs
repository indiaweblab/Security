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
        private static IRSAProvider _rsaProvider;

        static CryptoHelper()
        {
            _onewayhash = new OneWayHash();
            _aesprovider = new AESProvider();
            _rsaProvider = new RSAProvider();
        }

        public static XResult<String> GetMD5(String input)
        {
            return _onewayhash.GetMD5(input);
        }

        public static XResult<String> GetSHA1(String input, SHA1HashSize size = SHA1HashSize.SHA160)
        {
            return _onewayhash.GetSHA1(input, size);
        }

        public static XResult<String> AESEncrypt(String input, String key)
        {
            if (String.IsNullOrEmpty(input))
            {
                return new XResult<String>(null, new ArgumentNullException("The input value is null"));
            }

            if (String.IsNullOrEmpty(key))
            {
                return new XResult<String>(null, new ArgumentNullException("The key is null"));
            }

            try
            {
                return _aesprovider.Encrypt(input, new KeyManager(key));
            }
            catch (Exception ex)
            {
                return new XResult<String>(null, ex);
            }
        }

        public static XResult<String> AESDecrypt(String encryptedString, String key)
        {
            if (String.IsNullOrEmpty(encryptedString))
            {
                return new XResult<String>(null, new ArgumentNullException("The encrypted value is null"));
            }

            if (String.IsNullOrEmpty(key))
            {
                return new XResult<String>(null, new ArgumentNullException("The key is null"));
            }

            try
            {
                return _aesprovider.Decrypt(encryptedString, new KeyManager(key));
            }
            catch (Exception ex)
            {
                return new XResult<String>(null, ex);
            }
        }

        public static XResult<Byte[]> AESEncrypt(Stream stream, String key)
        {
            if (stream == null)
            {
                return new XResult<Byte[]>(null, new ArgumentNullException("The stream is null"));
            }

            if (String.IsNullOrEmpty(key))
            {
                return new XResult<Byte[]>(null, new ArgumentNullException("The key is null"));
            }

            try
            {
                return _aesprovider.Encrypt(stream, new KeyManager(key));
            }
            catch (Exception ex)
            {
                return new XResult<Byte[]>(null, ex);
            }
        }

        public static XResult<Byte[]> AESDecrypt(Stream stream, String key)
        {
            if (stream == null || stream.Length == 0)
            {
                return new XResult<Byte[]>(null, new ArgumentNullException("The stream is null"));
            }

            if (String.IsNullOrEmpty(key))
            {
                return new XResult<Byte[]>(null, new ArgumentNullException("The key is null or empty"));
            }

            try
            {
                return _aesprovider.Decrypt(stream, new KeyManager(key));
            }
            catch (Exception ex)
            {
                return new XResult<Byte[]>(null, ex);
            }
        }

        public static XResult<String> RSAEncrypt(String rawText, String publicKeyPem, SHA1HashSize hashSize, String charset = "UTF-8")
        {
            return _rsaProvider.Encrypt(rawText, publicKeyPem, hashSize, charset);
        }

        public static XResult<Byte[]> RSAEncrypt(Stream stream, String publicKeyPem, SHA1HashSize hashSize)
        {
            return _rsaProvider.Encrypt(stream, publicKeyPem, hashSize);
        }

        public static XResult<String> RSADecrypt(String encryptedString, String privateKeyPem, SHA1HashSize hashSize, String charset = "UTF-8")
        {
            return _rsaProvider.Decrypt(encryptedString, privateKeyPem, hashSize, charset);
        }

        public static XResult<Byte[]> RSADecrypt(Stream stream, String privateKeyPem, SHA1HashSize hashSize)
        {
            return _rsaProvider.Decrypt(stream, privateKeyPem, hashSize);
        }
    }
}
