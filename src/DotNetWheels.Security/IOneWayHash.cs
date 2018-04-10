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
        /// <summary>
        /// 获取输入字符串的MD5值
        /// </summary>
        /// <param name="input">输入的字符串</param>
        /// <returns></returns>
        String GetMD5(String input);

        /// <summary>
        /// 获取指定输入流的MD5值
        /// </summary>
        /// <param name="inputStream">输入流</param>
        /// <returns></returns>
        String GetMD5(Stream inputStream);

        /// <summary>
        /// 获取输入字符串的MD5值
        /// </summary>
        /// <param name="input">输入字符串</param>
        /// <param name="offset">字节数组中的偏移量，从该位置开始使用数据。</param>
        /// <param name="count">数组中用作数据的字节数。</param>
        /// <returns></returns>
        String GetMD5(String input, Int32 offset, Int32 count);

        /// <summary>
        /// 获取输入字符串的SHA1值
        /// </summary>
        /// <param name="input">输入的字符串</param>
        /// <returns></returns>
        String GetSHA1(String input);

        /// <summary>
        /// 获取指定输入流的SHA1值
        /// </summary>
        /// <param name="inputStream">输入流</param>
        /// <returns></returns>
        String GetSHA1(Stream inputStream);

        /// <summary>
        /// 获取输入字符串的SHA1值
        /// </summary>
        /// <param name="input">输入字符串</param>
        /// <param name="offset">字节数组中的偏移量，从该位置开始使用数据。</param>
        /// <param name="count">数组中用作数据的字节数。</param>
        /// <returns></returns>
        String GetSHA1(String input, Int32 offset, Int32 count);
    }
}
