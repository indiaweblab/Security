using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using DotNetWheels.Core;

namespace DotNetWheels.Security
{
    public interface IAESProvider
    {
        XResult<String> Encrypt(String rawText, KeyManager km, String charset = "UTF-8");
        XResult<String> Decrypt(String encryptedString, KeyManager km, String charset = "UTF-8");
        XResult<Byte[]> Encrypt(Stream stream, KeyManager km);
        XResult<Byte[]> Decrypt(Stream stream, KeyManager km);
    }
}
