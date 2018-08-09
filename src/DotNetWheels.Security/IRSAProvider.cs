using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using DotNetWheels.Core;

namespace DotNetWheels.Security
{
    public interface IRSAProvider
    {
        XResult<String> Encrypt(String rawText, String publicKeyPem, SHA1HashSize hashSize, String charset);
        XResult<Byte[]> Encrypt(Stream stream, String publicKeyPem, SHA1HashSize hashSize);
        XResult<String> Decrypt(String encryptedString, String privateKeyPem, SHA1HashSize hashSize, String charset);
        XResult<Byte[]> Decrypt(Byte[] encryptedData, String privateKeyPem, SHA1HashSize hashSize);
        XResult<Byte[]> Decrypt(Stream stream, String privateKeyPem, SHA1HashSize hashSize);
    }
}
