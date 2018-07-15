using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using DotNetWheels.Core;

namespace DotNetWheels.Security
{
    /// <summary>
    /// 单向函数
    /// </summary>
    public interface IOneWayHash
    {
        XResult<String> GetMD5(String input);
        XResult<String> GetMD5(Stream stream);
        XResult<String> GetSHA1(String input, SHA1HashSize size);
        XResult<String> GetSHA1(Stream stream, SHA1HashSize size);
        XResult<String> GetHMACSHA1(String input, String key);
        XResult<String> GetHMACSHA1Base64String(String input, String key);
    }
}
