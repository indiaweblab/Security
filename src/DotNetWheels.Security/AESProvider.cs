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

        public XResult<String> Encrypt(String rawText, KeyManager km)
        {
            var encryptedData = EncryptStringCore(rawText, km);
            if (encryptedData.Success)
            {
                String text = Convert.ToBase64String(encryptedData.Value);
                return ReplaceText(text);
            }

            return new XResult<String>(null, encryptedData.Exceptions.ToArray());
        }

        public XResult<String> Decrypt(String encryptedString, KeyManager km)
        {
            if (String.IsNullOrEmpty(encryptedString))
            {
                return new XResult<String>(null, new ArgumentException("encryptedString"));
            }

            Byte[] encrypted = null;
            try
            {
                var restoreResult = RestoreText(encryptedString);
                if (restoreResult.Success)
                {
                    encrypted = Convert.FromBase64String(restoreResult.Value);
                }
            }
            catch (Exception ex)
            {
                return new XResult<String>(null, ex);
            }

            return DecryptStringCore(encrypted, km);
        }

        public XResult<Byte[]> Encrypt(Stream stream, KeyManager km)
        {
            return EncryptStreamCore(stream, km);
        }

        public XResult<Byte[]> Decrypt(Byte[] encryptedData, KeyManager km)
        {
            return DecryptStreamCore(encryptedData, km);
        }

        public XResult<Byte[]> Decrypt(Stream stream, KeyManager km)
        {
            return DecryptStreamCore(stream, km);
        }

        private XResult<Byte[]> EncryptStringCore(String rawText, KeyManager km)
        {
            if (rawText == null || rawText.Length <= 0)
            {
                return new XResult<Byte[]>(null, new ArgumentNullException("rawText"));
            }

            if (km == null)
            {
                return new XResult<Byte[]>(null, new ArgumentNullException("km"));
            }

            Byte[] encrypted = null;
            Byte[] iv = new Byte[DefaultBlockSize / 8];

            XResult<String> sha1Result = _hash.GetSHA1(rawText, SHA1HashSize.SHA256);
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

                using (MemoryStream msEncrypt = new MemoryStream())
                {
                    CryptoStream csEncrypt = null;
                    try
                    {
                        csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write);

                        using (var swEncrypt = new StreamWriter(csEncrypt, Encoding.UTF8))
                        {
                            swEncrypt.Write(rawText);
                        }

                        encrypted = msEncrypt.ToArray();
                    }
                    catch (Exception ex)
                    {
                        return new XResult<Byte[]>(null, ex);
                    }
                    finally
                    {
                        if (csEncrypt != null) { csEncrypt.Dispose(); }
                    }
                }

                aesAlg.Clear();
            }

            Byte[] merged = new Byte[iv.Length + encrypted.Length];

            Array.Copy(iv, merged, iv.Length);
            Array.Copy(encrypted, 0, merged, iv.Length, encrypted.Length);

            return new XResult<Byte[]>(merged);
        }

        private XResult<String> DecryptStringCore(Byte[] encryptedData, KeyManager km)
        {
            if (encryptedData == null || encryptedData.Length <= 0)
            {
                return new XResult<String>(null, new ArgumentNullException("encryptedData"));
            }

            if (km == null)
            {
                return new XResult<String>(null, new ArgumentNullException("km"));
            }

            String plaintext = null;

            using (Aes aesAlg = Aes.Create())
            {
                aesAlg.KeySize = DefaultKeySize;
                aesAlg.BlockSize = DefaultBlockSize;
                aesAlg.Mode = DefaultCipherMode;
                aesAlg.Padding = DefaultPaddingMode;

                km.GenerateKey(DefaultKeySize);
                aesAlg.Key = km.Key;

                if (encryptedData.Length < aesAlg.IV.Length)
                {
                    return new XResult<String>(null, new ArgumentException("encryptedData isn't a valid data"));
                }

                Byte[] iv = new Byte[aesAlg.IV.Length];
                Array.Copy(encryptedData, iv, iv.Length);

                aesAlg.IV = iv;

                var decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);

                using (MemoryStream msDecrypt = new MemoryStream(encryptedData, aesAlg.IV.Length, encryptedData.Length - aesAlg.IV.Length))
                {
                    CryptoStream csDecrypt = null;
                    try
                    {
                        csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read);
                        using (var srDecrypt = new StreamReader(csDecrypt, Encoding.Default))
                        {
                            plaintext = srDecrypt.ReadToEnd();
                        }
                    }
                    catch (Exception ex)
                    {
                        return new XResult<String>(null, ex);
                    }
                    finally
                    {
                        if (csDecrypt != null) { csDecrypt.Dispose(); }
                    }
                }

                aesAlg.Clear();
            }

            return new XResult<String>(plaintext);
        }

        private XResult<Byte[]> EncryptStreamCore(Stream stream, KeyManager km)
        {
            if (stream == null || !stream.CanRead)
            {
                return new XResult<Byte[]>(null, new ArgumentNullException("The stream isn't support"));
            }

            if (km == null)
            {
                return new XResult<Byte[]>(null, new ArgumentNullException("The km is null"));
            }

            Byte[] encrypted = null;
            Byte[] iv = new Byte[DefaultBlockSize / 8];

            var sha1Result = _hash.GetSHA1(stream, SHA1HashSize.SHA256);
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

                using (MemoryStream msEncrypt = new MemoryStream())
                {
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
                    }
                }

                aesAlg.Clear();
            }

            Byte[] merged = new Byte[iv.Length + encrypted.Length];

            Array.Copy(iv, merged, iv.Length);
            Array.Copy(encrypted, 0, merged, iv.Length, encrypted.Length);

            return new XResult<Byte[]>(merged);
        }

        private XResult<Byte[]> DecryptStreamCore(Byte[] encryptedData, KeyManager km)
        {
            if (encryptedData == null || encryptedData.Length == 0)
            {
                return new XResult<Byte[]>(null, new ArgumentNullException("The encryptedData is null"));
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

                if (encryptedData.Length < aesAlg.IV.Length)
                {
                    return new XResult<Byte[]>(null, new ArgumentException("encryptedData isn't a valid data"));
                }

                Byte[] iv = new Byte[aesAlg.IV.Length];
                Array.Copy(encryptedData, iv, iv.Length);

                aesAlg.IV = iv;

                var decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);

                using (MemoryStream msDecrypt = new MemoryStream(encryptedData, iv.Length, encryptedData.Length - iv.Length))
                {
                    CryptoStream csDecrypt = null;
                    try
                    {
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
                    }
                }

                aesAlg.Clear();
            }

            return new XResult<Byte[]>(decryptedData);
        }

        private XResult<Byte[]> DecryptStreamCore(Stream stream, KeyManager km)
        {
            if (stream == null || stream.Length == 0)
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

                using (MemoryStream msDecrypt = new MemoryStream(data))
                {
                    CryptoStream csDecrypt = null;
                    try
                    {
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
                    }
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
