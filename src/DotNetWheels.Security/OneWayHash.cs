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
        /// 获取输入字符串的MD5值
        /// </summary>
        /// <param name="input">输入的字符串</param>
        /// <returns></returns>
        public String GetMD5(String input)
        {
            if (String.IsNullOrWhiteSpace(input))
            {
                return null;
            }

            return GetMD5(input, 0, input.Length);
        }

        /// <summary>
        /// 获取指定输入流的MD5值
        /// </summary>
        /// <param name="inputStream">输入流</param>
        /// <returns></returns>
        public String GetMD5(Stream inputStream)
        {
            if (inputStream == null)
            {
                return null;
            }

            Byte[] data;

            using (MD5 md5Hasher = MD5.Create())
            {
                data = md5Hasher.ComputeHash(inputStream);
            }

            if (data == null || data.Length == 0)
            {
                return String.Empty;
            }

            StringBuilder sBuilder = new StringBuilder();
            for (Int32 i = 0; i < data.Length; i++)
            {
                sBuilder.Append(data[i].ToString("x2"));
            }

            return sBuilder.ToString();
        }

        /// <summary>
        /// 获取输入字符串的MD5值
        /// </summary>
        /// <param name="input">输入字符串</param>
        /// <param name="offset">字节数组中的偏移量，从该位置开始使用数据。</param>
        /// <param name="count">数组中用作数据的字节数。</param>
        /// <returns></returns>
        public String GetMD5(String input, Int32 offset, Int32 count)
        {
            if (String.IsNullOrWhiteSpace(input))
            {
                return null;
            }

            Byte[] data;

            using (MD5 md5Hasher = MD5.Create())
            {
                data = md5Hasher.ComputeHash(Encoding.UTF8.GetBytes(input), offset, count);
            }

            if (data == null || data.Length == 0)
            {
                return null;
            }

            StringBuilder sBuilder = new StringBuilder();
            for (Int32 i = 0; i < data.Length; i++)
            {
                sBuilder.Append(data[i].ToString("x2"));
            }

            return sBuilder.ToString();
        }

        /// <summary>
        /// 获取输入字符串的SHA1值
        /// </summary>
        /// <param name="input">输入的字符串</param>
        /// <returns></returns>
        public String GetSHA1(String input)
        {
            if (String.IsNullOrWhiteSpace(input))
            {
                return null;
            }

            return GetSHA1(input, 0, input.Length);
        }

        /// <summary>
        /// 获取指定输入流的SHA1值
        /// </summary>
        /// <param name="inputStream">输入流</param>
        /// <returns></returns>
        public String GetSHA1(Stream inputStream)
        {
            if (inputStream == null)
            {
                return null;
            }

            Byte[] result;

            using (SHA1CryptoServiceProvider sh1csp = new SHA1CryptoServiceProvider())
            {
                result = sh1csp.ComputeHash(inputStream);
            }

            if (result == null || result.Length == 0)
            {
                return String.Empty;
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
        /// <param name="offset">字节数组中的偏移量，从该位置开始使用数据。</param>
        /// <param name="count">数组中用作数据的字节数。</param>
        /// <returns></returns>
        public String GetSHA1(String input, Int32 offset, Int32 count)
        {
            if (String.IsNullOrWhiteSpace(input))
            {
                return null;
            }

            Byte[] bytes = Encoding.UTF8.GetBytes(input), result;
            using (SHA1CryptoServiceProvider sh1csp = new SHA1CryptoServiceProvider())
            {
                result = sh1csp.ComputeHash(bytes, offset, count);
                sh1csp.Clear();
            }

            if (result == null || result.Length == 0)
            {
                return String.Empty;
            }

            StringBuilder sb = new StringBuilder();
            foreach (var b in result)
            {
                sb.Append(b.ToString("x2"));
            }

            return sb.ToString();
        }
    }
}
