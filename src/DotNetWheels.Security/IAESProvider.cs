using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace DotNetWheels.Security
{
    /// <summary>
    /// 
    /// </summary>
    public interface IAESProvider
    {
        /// <summary>
        /// Encrypts the input string with key and iv.
        /// </summary>
        /// <param name="input">The input string.</param>
        /// <param name="km"></param>
        String Encrypt(String input, KeyManager km);

        /// <summary>
        /// Decrypts the encrypted string with key and iv.
        /// </summary>
        /// <param name="encryptedString">The encrypted string.</param>
        /// <param name="km"></param>
        String Decrypt(String encryptedString, KeyManager km);
    }
}
