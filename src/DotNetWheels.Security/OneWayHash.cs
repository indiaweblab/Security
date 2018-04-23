using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace DotNetWheels.Security
{
    internal class OneWayHash : IOneWayHash
    {

        /// <summary>
        /// 获取指定输入流的MD5值
        /// </summary>
        /// <param name="stream">输入流</param>
        public String GetMD5(Stream stream)
        {
            if (stream == null)
            {
                return null;
            }

            Byte[] result = null;
            MD5 md5Hasher = null;

            try
            {
                md5Hasher = MD5.Create();
                result = md5Hasher.ComputeHash(stream);
            }
            catch
            {
                return null;
            }
            finally
            {
                if (md5Hasher != null)
                {
                    md5Hasher.Dispose();
                }
            }

            if (result == null || result.Length == 0)
            {
                return null;
            }

            StringBuilder sb = new StringBuilder();
            foreach (var b in result)
            {
                sb.Append(b.ToString("x2"));
            }

            return sb.ToString();
        }

        /// <summary>
        /// 获取输入字符串的MD5值
        /// </summary>
        /// <param name="input">输入字符串</param>
        public String GetMD5(String input)
        {
            if (String.IsNullOrEmpty(input))
            {
                return null;
            }

            Byte[] data = null;
            Byte[] result = null;
            MD5 md5Hasher = null;

            try
            {
                data = Encoding.UTF8.GetBytes(input);
                md5Hasher = MD5.Create();
                result = md5Hasher.ComputeHash(data);
            }
            catch
            {
                return null;
            }
            finally
            {
                if (md5Hasher != null)
                {
                    md5Hasher.Dispose();
                }
            }

            if (result == null || result.Length == 0)
            {
                return null;
            }

            StringBuilder sb = new StringBuilder();
            foreach (var b in result)
            {
                sb.Append(b.ToString("x2"));
            }

            return sb.ToString();
        }

        /// <summary>
        /// 获取指定输入流的SHA1值
        /// </summary>
        /// <param name="stream">输入流</param>
        /// <param name="size">算法所用的Hash大小</param>
        /// <returns></returns>
        public String GetSHA1(Stream stream, SHA1HashSize size = SHA1HashSize.SHA160)
        {
            if (stream == null)
            {
                return null;
            }

            Byte[] result = null;
            HashAlgorithm sh1csp = null;

            try
            {
                sh1csp = GetSHA1Algorithm(size);
                result = sh1csp.ComputeHash(stream);
            }
            catch
            {
                return null;
            }
            finally
            {
                if (sh1csp != null)
                {
                    sh1csp.Dispose();
                }
            }

            if (result == null || result.Length == 0)
            {
                return null;
            }

            StringBuilder sb = new StringBuilder();
            foreach (var b in result)
            {
                sb.Append(b.ToString("x2"));
            }

            return sb.ToString();
        }

        /// <summary>
        /// 获取输入字符串的SHA1值
        /// </summary>
        /// <param name="input">输入字符串</param>
        /// <param name="size">算法所用的Hash大小</param>
        public String GetSHA1(String input, SHA1HashSize size = SHA1HashSize.SHA160)
        {
            if (String.IsNullOrEmpty(input))
            {
                return null;
            }

            Byte[] data = null;
            Byte[] result = null;
            HashAlgorithm sh1csp = null;

            try
            {
                data = Encoding.UTF8.GetBytes(input);
                sh1csp = GetSHA1Algorithm(size);
                result = sh1csp.ComputeHash(data);
            }
            catch
            {
                return null;
            }
            finally
            {
                if (sh1csp != null)
                {
                    sh1csp.Dispose();
                }
            }

            if (result == null || result.Length == 0)
            {
                return null;
            }

            StringBuilder sb = new StringBuilder();
            foreach (var b in result)
            {
                sb.Append(b.ToString("x2"));
            }

            return sb.ToString();
        }

        private HashAlgorithm GetSHA1Algorithm(SHA1HashSize size)
        {
            switch (size)
            {
                case SHA1HashSize.SHA256:
                    return new SHA256Managed();
                case SHA1HashSize.SHA512:
                    return new SHA512Managed();
                default:
                    return new SHA1Managed();
            }
        }
    }
}
