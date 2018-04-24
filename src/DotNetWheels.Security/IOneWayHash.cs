using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace DotNetWheels.Security
{
    /// <summary>
    /// 单向函数
    /// </summary>
    public interface IOneWayHash
    {
        String GetMD5(String input);
        String GetMD5(Stream stream);
        String GetSHA1(String input, SHA1HashSize size);
        String GetSHA1(Stream stream, SHA1HashSize size);
    }
}
