using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Threading;

namespace DotNetWheels.Security
{
    /// <summary>
    /// 加密解密助手类
    /// </summary>
    public static class CryptoHelper
    {

        private static IOneWayHash _onewayhash;
        private static IAESProvider _aesprovider;

        static CryptoHelper()
        {
            _onewayhash = new OneWayHash();
            _aesprovider = new AESProvider();
        }

        /// <summary>
        /// Gets the MD5 value of input string.
        /// </summary>
        /// <param name="input">The input string.</param>
        public static String GetMD5(String input)
        {
            return _onewayhash.GetMD5(input);
        }

        /// <summary>
        /// Gets the SHA1 value of input string.
        /// </summary>
        /// <param name="input">The input string.</param>
        /// <param name="size">Hash size used by the algorithm.</param>
        public static String GetSHA1(String input, SHA1HashSize size = SHA1HashSize.SHA160)
        {
            return _onewayhash.GetSHA1(input, size);
        }

        /// <summary>
        /// Encrypts the input string using AES provider with the key.
        /// </summary>
        /// <param name="input"></param>
        /// <param name="key"></param>
        public static String Encrypt(String input, String key)
        {
            if (String.IsNullOrEmpty(input))
            {
                throw new ArgumentNullException("The input value is null");
            }

            if (String.IsNullOrEmpty(key))
            {
                throw new ArgumentNullException("The key is null");
            }

            return _aesprovider.Encrypt(input, new KeyManager(key));
        }

        /// <summary>
        /// Decrypts the encryped string using AES provider with the key.
        /// </summary>
        /// <param name="encryptedString"></param>
        /// <param name="key"></param>
        public static String Decrypt(String encryptedString, String key)
        {
            if (String.IsNullOrEmpty(encryptedString))
            {
                throw new ArgumentNullException("The encrypted value is null");
            }

            if (String.IsNullOrEmpty(key))
            {
                throw new ArgumentNullException("The key is null");
            }

            return _aesprovider.Decrypt(encryptedString, new KeyManager(key));
        }

    }
}
