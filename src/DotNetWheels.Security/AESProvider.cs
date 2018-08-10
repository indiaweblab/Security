using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using DotNetWheels.Core;

namespace DotNetWheels.Security
{
    internal class AESProvider : IAESProvider
    {
        private const Int32 DefaultKeySize = 256;
        private const Int32 DefaultBlockSize = 128;
        private const CipherMode DefaultCipherMode = CipherMode.CBC;
        private const PaddingMode DefaultPaddingMode = PaddingMode.PKCS7;
        private static IOneWayHash _hash = new OneWayHash();

        public XResult<String> Encrypt(String rawText, KeyManager km, String charset = "UTF-8")
        {
            if (String.IsNullOrWhiteSpace(rawText))
            {
                return new XResult<String>(null, new ArgumentNullException("rawText is null"));
            }

            if (km == null)
            {
                return new XResult<String>(null, new ArgumentNullException("km"));
            }

            Byte[] inputData = null;
            try
            {
                inputData = Encoding.GetEncoding(charset).GetBytes(rawText);
            }
            catch (Exception ex)
            {
                return new XResult<String>(null, ex);
            }

            MemoryStream ms = null;
            try
            {
                ms = new MemoryStream(inputData);
                var result = Encrypt(ms, km);
                if (result.Success)
                {
                    String encryptedBase64String = Convert.ToBase64String(result.Value);
                    return ReplaceText(encryptedBase64String);
                }
                else
                {
                    return new XResult<String>(null, result.Exceptions.ToArray());
                }
            }
            catch (Exception ex)
            {
                return new XResult<String>(null, ex);
            }
            finally
            {
                if (ms != null) { ms.Dispose(); }
            }
        }

        public XResult<String> Decrypt(String encryptedString, KeyManager km, String charset = "UTF-8")
        {
            if (String.IsNullOrEmpty(encryptedString))
            {
                return new XResult<String>(null, new ArgumentNullException("encryptedString is null"));
            }

            if (km == null)
            {
                return new XResult<String>(null, new ArgumentNullException("km is null"));
            }

            Byte[] toEncrypt = null;
            try
            {
                var restoreResult = RestoreText(encryptedString);
                toEncrypt = Convert.FromBase64String(restoreResult.Value);
            }
            catch (Exception ex)
            {
                return new XResult<String>(null, ex);
            }

            MemoryStream ms = null;
            try
            {
                ms = new MemoryStream(toEncrypt);
                var result = Decrypt(ms, km);
                if (result.Success)
                {
                    String decryptedString = Encoding.GetEncoding(charset).GetString(result.Value);
                    return new XResult<String>(decryptedString);
                }
                else
                {
                    return new XResult<String>(null, result.Exceptions.ToArray());
                }
            }
            catch (Exception ex)
            {
                return new XResult<String>(null, ex);
            }
            finally
            {
                if (ms != null) { ms.Dispose(); }
            }
        }

        public XResult<Byte[]> Encrypt(Stream stream, KeyManager km)
        {
            if (stream == null || stream.Length == 0 || !stream.CanRead)
            {
                return new XResult<Byte[]>(null, new ArgumentNullException("The stream isn't support"));
            }

            if (km == null)
            {
                return new XResult<Byte[]>(null, new ArgumentNullException("The km is null"));
            }

            Byte[] encrypted = null;
            Byte[] iv = new Byte[DefaultBlockSize / 8];

            var sha1Result = _hash.GetSHA(stream, HashAlgorithmName.SHA256);
            if (!sha1Result.Success)
            {
                return new XResult<Byte[]>(null, new CryptographicException("IV generate failed"));
            }

            Byte[] bytes = Encoding.ASCII.GetBytes(sha1Result.Value);
            Array.Copy(bytes, iv, iv.Length);

            using (Aes aesAlg = Aes.Create())
            {
                aesAlg.KeySize = DefaultKeySize;
                aesAlg.BlockSize = DefaultBlockSize;
                aesAlg.Mode = DefaultCipherMode;
                aesAlg.Padding = DefaultPaddingMode;

                km.GenerateKey(DefaultKeySize);
                aesAlg.Key = km.Key;
                aesAlg.IV = iv;

                var encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);

                var msEncrypt = new MemoryStream();
                CryptoStream csEncrypt = null;
                try
                {
                    csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write);

                    Byte[] buffer = new Byte[2048];
                    Int32 read = 0;
                    stream.Position = 0;

                    while ((read = stream.Read(buffer, 0, buffer.Length)) > 0)
                    {
                        csEncrypt.Write(buffer, 0, read);
                    }

                    csEncrypt.FlushFinalBlock();//this place can't lost.
                    encrypted = msEncrypt.ToArray();
                }
                catch (Exception ex)
                {
                    return new XResult<Byte[]>(null, ex);
                }
                finally
                {
                    if (csEncrypt != null) { csEncrypt.Dispose(); }
                    msEncrypt.Dispose();
                }

                aesAlg.Clear();
            }

            Byte[] merged = new Byte[iv.Length + encrypted.Length];

            Array.Copy(iv, merged, iv.Length);
            Array.Copy(encrypted, 0, merged, iv.Length, encrypted.Length);

            return new XResult<Byte[]>(merged);
        }

        public XResult<Byte[]> Decrypt(Stream stream, KeyManager km)
        {
            if (stream == null || stream.Length == 0 || !stream.CanRead)
            {
                return new XResult<Byte[]>(null, new ArgumentNullException("The stream is null"));
            }

            if (km == null)
            {
                return new XResult<Byte[]>(null, new ArgumentNullException("km"));
            }

            Byte[] decryptedData = null;

            using (Aes aesAlg = Aes.Create())
            {
                aesAlg.KeySize = DefaultKeySize;
                aesAlg.BlockSize = DefaultBlockSize;
                aesAlg.Mode = DefaultCipherMode;
                aesAlg.Padding = DefaultPaddingMode;

                km.GenerateKey(DefaultKeySize);
                aesAlg.Key = km.Key;

                if (stream.Length < aesAlg.IV.Length)
                {
                    return new XResult<Byte[]>(null, new ArgumentException("stream isn't a valid stream"));
                }

                Byte[] iv = new Byte[aesAlg.IV.Length];
                stream.Read(iv, 0, iv.Length);

                aesAlg.IV = iv;

                var decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);

                Byte[] data = new Byte[stream.Length - iv.Length];
                stream.Read(data, 0, data.Length);
                stream.Flush();

                MemoryStream msDecrypt = null;
                CryptoStream csDecrypt = null;
                try
                {
                    msDecrypt = new MemoryStream(data);
                    csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read);

                    Byte[] buffer = new Byte[2048];
                    Int32 read = 0;

                    using (MemoryStream resultStream = new MemoryStream())
                    {
                        while ((read = csDecrypt.Read(buffer, 0, buffer.Length)) > 0)
                        {
                            resultStream.Write(buffer, 0, read);
                        }

                        decryptedData = resultStream.ToArray();
                    }
                }
                catch (Exception ex)
                {
                    return new XResult<Byte[]>(null, ex);
                }
                finally
                {
                    if (csDecrypt != null) { csDecrypt.Dispose(); }
                    if (msDecrypt != null) { msDecrypt.Dispose(); }
                }

                aesAlg.Clear();
            }

            return new XResult<Byte[]>(decryptedData);
        }

        private XResult<String> ReplaceText(String base64String)
        {
            return new XResult<String>(base64String.Replace('+', '!').Replace('/', '-').Replace('=', '_'));
        }

        private XResult<String> RestoreText(String replacedText)
        {
            return new XResult<String>(replacedText.Replace('!', '+').Replace('-', '/').Replace('_', '='));
        }
    }
}
