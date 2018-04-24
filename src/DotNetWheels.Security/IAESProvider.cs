using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace DotNetWheels.Security
{
    public interface IAESProvider
    {
        String Encrypt(String rawText, KeyManager km);
        String Decrypt(String encryptedString, KeyManager km);
        Byte[] Encrypt(Stream stream, KeyManager km);
        Byte[] Decrypt(Byte[] encryptedData, KeyManager km);
        Byte[] Decrypt(Stream stream, KeyManager km);
    }
}
