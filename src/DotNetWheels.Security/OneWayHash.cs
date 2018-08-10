using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using DotNetWheels.Core;

namespace DotNetWheels.Security
{
    internal class OneWayHash : IOneWayHash
    {
        public XResult<String> GetMD5(Stream stream)
        {
            if (stream == null || stream.Length == 0)
            {
                return new XResult<String>(null, new ArgumentNullException("stream"));
            }

            Byte[] result = null;
            MD5 md5Hasher = null;

            try
            {
                md5Hasher = MD5.Create();
                result = md5Hasher.ComputeHash(stream);
            }
            catch (Exception ex)
            {
                return new XResult<String>(null, ex);
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
                return new XResult<String>(null, new ArgumentNullException("the computed result is null"));
            }

            StringBuilder sb = new StringBuilder();
            foreach (var b in result)
            {
                sb.Append(b.ToString("x2"));
            }

            return new XResult<String>(sb.ToString());
        }

        public XResult<String> GetMD5(String input)
        {
            if (String.IsNullOrEmpty(input))
            {
                return new XResult<String>(null, new ArgumentNullException("input"));
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
            catch (Exception ex)
            {
                return new XResult<String>(null, ex);
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

            return new XResult<String>(sb.ToString());
        }

        public XResult<String> GetSHA(Stream stream, HashAlgorithmName algName)
        {
            if (stream == null || stream.Length == 0)
            {
                return new XResult<String>(null, new ArgumentNullException("stream"));
            }

            Byte[] result = null;
            HashAlgorithm sh1csp = null;

            try
            {
                sh1csp = GetSHA1Algorithm(algName);
                result = sh1csp.ComputeHash(stream);
            }
            catch (Exception ex)
            {
                return new XResult<String>(null, ex); ;
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
                return new XResult<String>(null, new ArgumentNullException("the computed result is null")); ;
            }

            StringBuilder sb = new StringBuilder();
            foreach (var b in result)
            {
                sb.Append(b.ToString("x2"));
            }

            return new XResult<String>(sb.ToString());
        }

        public XResult<String> GetSHA(String input, HashAlgorithmName algName)
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
                sh1csp = GetSHA1Algorithm(algName);
                result = sh1csp.ComputeHash(data);
            }
            catch (Exception ex)
            {
                return new XResult<String>(null, ex);
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
                return new XResult<String>(null, new ArgumentNullException("the computed result is null"));
            }

            StringBuilder sb = new StringBuilder();
            foreach (var b in result)
            {
                sb.Append(b.ToString("x2"));
            }

            return new XResult<String>(sb.ToString());
        }

        public XResult<String> GetHMACSHA1(String input, String key)
        {
            if (String.IsNullOrWhiteSpace(input))
            {
                return new XResult<String>(null, new ArgumentNullException("input"));
            }

            if (String.IsNullOrWhiteSpace(key))
            {
                return new XResult<String>(null, new ArgumentNullException("key"));
            }

            Byte[] keyData = null;
            try
            {
                keyData = Encoding.UTF8.GetBytes(key);
            }
            catch (Exception ex)
            {
                return new XResult<String>(null, ex);
            }

            Byte[] inputData = null;
            try
            {
                inputData = Encoding.UTF8.GetBytes(input);
            }
            catch (Exception ex)
            {
                return new XResult<String>(null, ex);
            }

            HMACSHA1 hmac = null;
            Byte[] result = null;
            try
            {
                hmac = new HMACSHA1(keyData);
                result = hmac.ComputeHash(inputData);
            }
            catch (Exception ex)
            {
                return new XResult<String>(null, ex);
            }

            if (result == null || result.Length == 0)
            {
                return new XResult<String>(null, new ArgumentNullException("hmac.ComputeHash(inputData) returns null"));
            }

            StringBuilder sb = new StringBuilder();
            foreach (var b in result)
            {
                sb.Append(b.ToString("x2"));
            }

            return new XResult<String>(sb.ToString());
        }

        public XResult<String> GetHMACSHA1Base64String(String input, String key)
        {
            if (String.IsNullOrWhiteSpace(input))
            {
                return new XResult<String>(null, new ArgumentNullException("input"));
            }

            if (String.IsNullOrWhiteSpace(key))
            {
                return new XResult<String>(null, new ArgumentNullException("key"));
            }

            Byte[] keyData = null;
            try
            {
                keyData = Encoding.UTF8.GetBytes(key);
            }
            catch (Exception ex)
            {
                return new XResult<String>(null, ex);
            }

            Byte[] inputData = null;
            try
            {
                inputData = Encoding.UTF8.GetBytes(input);
            }
            catch (Exception ex)
            {
                return new XResult<String>(null, ex);
            }

            HMACSHA1 hmac = null;
            Byte[] result = null;

            try
            {
                hmac = new HMACSHA1(keyData);
                result = hmac.ComputeHash(inputData);
            }
            catch (Exception ex)
            {
                return new XResult<String>(null, ex);
            }

            if (result == null || result.Length == 0)
            {
                return new XResult<String>(null, new ArgumentNullException("the computed result is null"));
            }

            return new XResult<String>(Convert.ToBase64String(result));
        }

        private HashAlgorithm GetSHA1Algorithm(HashAlgorithmName algName)
        {
            switch (algName.Name)
            {
                case "SHA512":
                    return SHA512.Create();
                case "SHA384":
                    return SHA384.Create();
                case "SHA256":
                    return SHA256.Create();
                case "SHA1":
                    return SHA1.Create();
                case "MD5":
                    return MD5.Create();
                default:
                    throw new InvalidOperationException();
            }
        }
    }
}
