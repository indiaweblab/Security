using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace DotNetWheels.Security
{
    internal class AESProvider : IAESProvider
    {
        private const Int32 KeySize = 256;
        private const Int32 BlockSize = 128;
        private const PaddingMode DefaultPaddingMode = PaddingMode.PKCS7;
        private static IOneWayHash _hash = new OneWayHash();

        public String Encrypt(String input, KeyManager km)
        {
            var encryptedData = EncryptStringToBytes_Aes(input, km);
            String text = Convert.ToBase64String(encryptedData);
            return ReplaceText(text);
        }
        public Byte[] Encrypt(Stream input, KeyManager km)
        {
            return EncryptStream_Aes(input, km);
        }

        public String Decrypt(String encryptedString, KeyManager km)
        {
            if (String.IsNullOrEmpty(encryptedString))
            {
                return encryptedString;
            }

            Byte[] encrypted;

            try
            {
                encrypted = Convert.FromBase64String(RestoreText(encryptedString));
            }
            catch (Exception)
            {
                return null;
            }

            return DecryptStringFromBytes_Aes(encrypted, km);
        }
        public Byte[] Decrypt(Byte[] encryptedData, KeyManager km)
        {
            return DecryptStream_Aes(encryptedData, km);
        }

        private Byte[] EncryptStringToBytes_Aes(String plainText, KeyManager km)
        {
            if (plainText == null || plainText.Length <= 0)
            {
                throw new ArgumentNullException("plainText");
            }

            if (km == null)
            {
                throw new ArgumentNullException("km");
            }

            Byte[] encrypted = null;
            Byte[] iv = new Byte[BlockSize / 8];
            Byte[] bytes = Encoding.ASCII.GetBytes(_hash.GetSHA1(plainText, SHA1HashSize.SHA256));
            Array.Copy(bytes, iv, iv.Length);

            using (Aes aesAlg = Aes.Create())
            {
                aesAlg.KeySize = KeySize;
                aesAlg.BlockSize = BlockSize;

                km.GenerateKey(KeySize);
                aesAlg.Key = km.Key;
                aesAlg.IV = iv;

                File.AppendAllText(@"C:\1.txt", "加密IV:" + String.Join(",", iv) + Environment.NewLine, Encoding.UTF8);

                var encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);

                using (MemoryStream msEncrypt = new MemoryStream())
                {
                    CryptoStream csEncrypt = null;
                    try
                    {
                        csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write);

                        using (var swEncrypt = new StreamWriter(csEncrypt, Encoding.UTF8))
                        {
                            swEncrypt.Write(plainText);
                        }

                        encrypted = msEncrypt.ToArray();
                    }
                    catch (Exception ex)
                    {
                        throw ex;
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

            File.AppendAllText(@"C:\1.txt", "加密的数组:" + String.Join(",", merged) + Environment.NewLine, Encoding.UTF8);

            return merged;
        }
        private Byte[] EncryptStream_Aes(Stream stream, KeyManager km)
        {
            if (stream == null || !stream.CanRead)
            {
                throw new ArgumentNullException("The stream isn't support");
            }

            if (km == null)
            {
                throw new ArgumentNullException("The km is null");
            }

            Byte[] encrypted = null;

            using (Aes aesAlg = Aes.Create())
            {
                aesAlg.KeySize = KeySize;
                aesAlg.BlockSize = BlockSize;
                aesAlg.Padding = PaddingMode.Zeros;

                km.GenerateKey(KeySize);
                aesAlg.Key = km.Key;

                var encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);

                MemoryStream msEncrypt = null;
                CryptoStream csEncrypt = null;
                try
                {
                    msEncrypt = new MemoryStream();
                    csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write);

                    Byte[] buffer = new Byte[2048];
                    Int32 read = 0;

                    while ((read = stream.Read(buffer, 0, buffer.Length)) > 0)
                    {
                        csEncrypt.Write(buffer, 0, read);
                    }

                    encrypted = msEncrypt.ToArray();
                }
                catch (Exception ex)
                {
                    throw ex;
                }
                finally
                {
                    if (csEncrypt != null) { csEncrypt.Dispose(); }
                    if (msEncrypt != null) { msEncrypt.Dispose(); }
                }

                aesAlg.Clear();
            }

            return encrypted;
        }

        private String DecryptStringFromBytes_Aes(Byte[] cipherText, KeyManager km)
        {
            if (cipherText == null || cipherText.Length <= 0)
            {
                throw new ArgumentNullException("cipherText");
            }

            if (km == null)
            {
                throw new ArgumentNullException("km");
            }

            File.AppendAllText(@"C:\1.txt", "需要解密的数组:" + String.Join(",", cipherText) + Environment.NewLine, Encoding.UTF8);

            String plaintext = null;

            using (Aes aesAlg = Aes.Create())
            {
                aesAlg.KeySize = KeySize;
                aesAlg.BlockSize = BlockSize;

                km.GenerateKey(KeySize);
                aesAlg.Key = km.Key;

                if (cipherText.Length < aesAlg.IV.Length)
                {
                    throw new ArgumentException("cipherText isn't a valid data");
                }

                Byte[] iv = new Byte[aesAlg.IV.Length];
                for (var i = 0; i < iv.Length; i++)
                {
                    iv[i] = cipherText[i];
                }

                aesAlg.IV = iv;

                var decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);

                File.AppendAllText(@"C:\1.txt", "解密使用的IV:" + String.Join(",", aesAlg.IV) + Environment.NewLine, Encoding.UTF8);

                using (MemoryStream msDecrypt = new MemoryStream(cipherText, aesAlg.IV.Length, cipherText.Length - aesAlg.IV.Length))
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
                        throw ex;
                    }
                    finally
                    {
                        if (csDecrypt != null) { csDecrypt.Dispose(); }
                    }
                }

                aesAlg.Clear();
            }
            return plaintext;
        }
        private Byte[] DecryptStream_Aes(Byte[] encryptedData, KeyManager km)
        {
            if (encryptedData == null || encryptedData.Length == 0)
            {
                throw new ArgumentNullException("The encryptedData is null");
            }

            if (km == null)
            {
                throw new ArgumentNullException("km");
            }

            Byte[] decryptedData = null;

            using (Aes aesAlg = Aes.Create())
            {

                aesAlg.KeySize = KeySize;
                aesAlg.BlockSize = BlockSize;
                aesAlg.Padding = PaddingMode.Zeros;

                km.GenerateKey(KeySize);

                aesAlg.Key = km.Key;
                var decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);

                MemoryStream msDecrypt = null;
                CryptoStream csDecrypt = null;
                try
                {
                    msDecrypt = new MemoryStream(encryptedData);
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
                    throw ex;
                }
                finally
                {
                    if (csDecrypt != null) { csDecrypt.Dispose(); }
                    if (msDecrypt != null) { msDecrypt.Dispose(); }
                }

                aesAlg.Clear();
            }

            return decryptedData;
        }

        private String ReplaceText(String text)
        {
            return text.Replace('+', '!').Replace('/', '-').Replace('=', '_');
        }

        private String RestoreText(String text)
        {
            return text.Replace('!', '+').Replace('-', '/').Replace('_', '=');
        }
    }
}
