﻿using System;
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
        private const PaddingMode PaddingMode = System.Security.Cryptography.PaddingMode.PKCS7;

        /// <summary>
        /// Encrypts the input string with key and iv.
        /// </summary>
        /// <param name="input">The input string.</param>
        /// <param name="km"></param>
        public String Encrypt(String input, KeyManager km)
        {
            var encryptedData = EncryptStringToBytes_Aes(input, km);
            String text = Convert.ToBase64String(encryptedData);
            return ReplaceText(text);
        }

        /// <summary>
        /// Decrypts the encrypted string with key and iv.
        /// </summary>
        /// <param name="encryptedString">The encrypted string.</param>
        /// <param name="km"></param>
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

        private Byte[] EncryptStringToBytes_Aes(String plainText, KeyManager km)
        {
            // Check arguments.
            if (plainText == null || plainText.Length <= 0)
            {
                throw new ArgumentNullException("plainText");
            }

            if (km == null)
            {
                throw new ArgumentNullException("km");
            }

            Byte[] encrypted = null;

            // Create an Aes object
            // with the specified key and IV.
            using (Aes aesAlg = Aes.Create())
            {

                aesAlg.KeySize = KeySize;
                aesAlg.BlockSize = BlockSize;
                aesAlg.Padding = PaddingMode;

                km.GenerateKeyAndIV(KeySize, BlockSize);

                aesAlg.Key = km.Key;
                aesAlg.IV = km.IV;

                // Create a decrytor to perform the stream transform.
                ICryptoTransform encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);

                // Create the streams used for encryption.
                using (MemoryStream msEncrypt = new MemoryStream())
                {
                    CryptoStream csEncrypt = null;
                    try
                    {
                        csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write);
                        using (var swEncrypt = new StreamWriter(csEncrypt))
                        {
                            //Write all data to the stream.
                            swEncrypt.Write(plainText);
                        }
                        encrypted = msEncrypt.ToArray();
                    }
                    catch (Exception) { }
                    finally
                    {
                        if (csEncrypt != null) { csEncrypt.Dispose(); }
                    }
                }

                aesAlg.Clear();
            }

            // Return the encrypted bytes from the memory stream.
            return encrypted;

        }
        private String DecryptStringFromBytes_Aes(Byte[] cipherText, KeyManager km)
        {
            // Check arguments.
            if (cipherText == null || cipherText.Length <= 0)
            {
                throw new ArgumentNullException("cipherText");
            }

            if (km == null)
            {
                throw new ArgumentNullException("km");
            }

            // Declare the string used to hold
            // the decrypted text.
            String plaintext = null;

            // Create an Aes object
            // with the specified key and IV.
            using (Aes aesAlg = Aes.Create())
            {

                aesAlg.KeySize = KeySize;
                aesAlg.BlockSize = BlockSize;
                aesAlg.Padding = PaddingMode;

                km.GenerateKeyAndIV(KeySize, BlockSize);

                aesAlg.Key = km.Key;
                aesAlg.IV = km.IV;

                // Create a decrytor to perform the stream transform.
                ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);

                // Create the streams used for decryption.
                using (MemoryStream msDecrypt = new MemoryStream(cipherText))
                {
                    CryptoStream csDecrypt = null;
                    try
                    {
                        csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read);
                        using (var srDecrypt = new StreamReader(csDecrypt))
                        {
                            // Read the decrypted bytes from the decrypting stream
                            // and place them in a string.
                            plaintext = srDecrypt.ReadToEnd();
                        }
                    }
                    catch (Exception) { }
                    finally
                    {
                        if (csDecrypt != null) { csDecrypt.Dispose(); }
                    }
                }

                aesAlg.Clear();
            }
            return plaintext;
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