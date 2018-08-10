using DotNetWheels.Security;
using System;
using System.Diagnostics;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using Xunit;

namespace DotNetWheelsSecurityTests
{
    public class CryptoHelperTest
    {
        private static readonly String _privateKey = @"MIICXgIBAAKBgQC0xP5HcfThSQr43bAMoopbzcCyZWE0xfUeTA4Nx4PrXEfDvybJ
EIjbU/rgANAty1yp7g20J7+wVMPCusxftl/d0rPQiCLjeZ3HtlRKld+9htAZtHFZ
osV29h/hNE9JkxzGXstaSeXIUIWquMZQ8XyscIHhqoOmjXaCv58CSRAlAQIDAQAB
AoGBAJtDgCwZYv2FYVk0ABw6F6CWbuZLUVykks69AG0xasti7Xjh3AximUnZLefs
iuJqg2KpRzfv1CM+Cw5cp2GmIVvRqq0GlRZGxJ38AqH9oyUa2m3TojxWapY47zye
PYEjWwRTGlxUBkdujdcYj6/dojNkm4azsDXl9W5YaXiPfbgJAkEA4rlhSPXlohDk
FoyfX0v2OIdaTOcVpinv1jjbSzZ8KZACggjiNUVrSFV3Y4oWom93K5JLXf2mV0Sy
80mPR5jOdwJBAMwciAk8xyQKpMUGNhFX2jKboAYY1SJCfuUnyXHAPWeHp5xCL2UH
tjryJp/Vx8TgsFTGyWSyIE9R8hSup+32rkcCQBe+EAkC7yQ0np4Z5cql+sfarMMm
4+Z9t8b4N0a+EuyLTyfs5Dtt5JkzkggTeuFRyOoALPJP0K6M3CyMBHwb7WsCQQCi
TM2fCsUO06fRQu8bO1A1janhLz3K0DU24jw8RzCMckHE7pvhKhCtLn+n+MWwtzl/
L9JUT4+BgxeLepXtkolhAkEA2V7er7fnEuL0+kKIjmOm5F3kvMIDh9YC1JwLGSvu
1fnzxK34QwSdxgQRF1dfIKJw73lClQpHZfQxL/2XRG8IoA==";

        //openssl rsa -pubout -in rsa_1024_priv.pem -out rsa_1024_pub.pem
        private static readonly String _publicKey = @"MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC0xP5HcfThSQr43bAMoopbzcCy
ZWE0xfUeTA4Nx4PrXEfDvybJEIjbU/rgANAty1yp7g20J7+wVMPCusxftl/d0rPQ
iCLjeZ3HtlRKld+9htAZtHFZosV29h/hNE9JkxzGXstaSeXIUIWquMZQ8XyscIHh
qoOmjXaCv58CSRAlAQIDAQAB";

        [Fact]
        public void TestAESEncryptString()
        {
            String rawText = "I love you!";
            var result = CryptoHelper.AESEncrypt(rawText, "123");
            Assert.Equal("YzIyZmUwMjgyYzdiNDViMBFY0JT2IiS-8oRE1oR4UKQ_", result.Value);
        }

        [Fact]
        public void TestAESDecryptString()
        {
            String encryptedText = "YzIyZmUwMjgyYzdiNDViMBFY0JT2IiS-8oRE1oR4UKQ_";
            var result = CryptoHelper.AESDecrypt(encryptedText, "123");
            Assert.Equal("I love you!", result.Value);
        }

        [Fact]
        public void TestAESEncryptStream()
        {
            var rawData = Encoding.ASCII.GetBytes("I love you, My Girl!");

            Byte[] encryptedData = null;
            using (var ms = new MemoryStream(rawData))
            {
                var data = CryptoHelper.AESEncrypt(ms, "123");
                encryptedData = data.Value;
            }

            Assert.NotNull(encryptedData);

            var result = String.Join(",", encryptedData);
            Assert.Equal("52,56,101,50,54,53,100,98,49,50,49,102,99,48,99,56,157,22,200,98,25,57,147,186,0,106,97,243,137,181,71,47,66,157,70,190,25,106,218,69,50,112,107,149,181,202,36,104", result);
        }

        [Fact]
        public void TestAESDecryptStream()
        {
            String[] chars = "52,56,101,50,54,53,100,98,49,50,49,102,99,48,99,56,157,22,200,98,25,57,147,186,0,106,97,243,137,181,71,47,66,157,70,190,25,106,218,69,50,112,107,149,181,202,36,104".Split(',');
            Byte[] encryptedData = new Byte[chars.Length];
            for (var i = 0; i < chars.Length; i++)
            {
                encryptedData[i] = Byte.Parse(chars[i]);
            }

            using (var ms = new MemoryStream(encryptedData))
            {
                var decryptedData = CryptoHelper.AESDecrypt(ms, "123");
                var result = Encoding.ASCII.GetString(decryptedData.Value);

                Assert.Equal("I love you, My Girl!", result);
            }
        }

        [Fact]
        public void TestAESEncryptFile()
        {
            String filePath = @"F:\需要加密的文件\test_enc_orig.jpg";
            Byte[] encryptedData = null;

            using (var fs = File.Open(filePath, FileMode.Open, FileAccess.Read))
            {
                var data = CryptoHelper.AESEncrypt(fs, "1234");
                encryptedData = data.Value;
            }

            Assert.True(encryptedData != null && encryptedData.Length > 0);

            File.WriteAllBytes(@"F:\需要加密的文件\test_enc.jpg", encryptedData);
        }

        [Fact]
        public void TestAESDecryptFile()
        {
            String encryptedFilePath = @"F:\需要加密的文件\test_dec_orig.jpg";
            Byte[] decryptedData = null;

            using (var fs = File.Open(encryptedFilePath, FileMode.Open, FileAccess.Read))
            {
                var data = CryptoHelper.AESDecrypt(fs, "1234");
                decryptedData = data.Value;
            }

            Assert.True(decryptedData != null && decryptedData.Length > 0);

            File.WriteAllBytes(@"F:\需要加密的文件\test_dec.jpg", decryptedData);
        }

        [Fact]
        public void TestRSAEncryptAndDecryptText()
        {
            String rawText = "I love you!";
            var encResult = CryptoHelper.RSAEncrypt(rawText, _publicKey);
            Assert.True(encResult.Success);

            var decResult = CryptoHelper.RSADecrypt(encResult.Value, _privateKey);
            Assert.True(decResult.Success);
            String decText = decResult.Value;

            Assert.Equal(rawText, decText);
        }

        [Fact]
        public void TestRSAEncryptAndDecryptWithBigText()
        {
            String rawText = @"MIICXgIBAAKBgQC0xP5HcfThSQr43bAMoopbzcCyZWE0xfUeTA4Nx4PrXEfDvybJ
EIjbU/rgANAty1yp7g20J7+wVMPCusxftl/d0rPQiCLjeZ3HtlRKld+9htAZtHFZ
osV29h/hNE9JkxzGXstaSeXIUIWquMZQ8XyscIHhqoOmjXaCv58CSRAlAQIDAQAB
AoGBAJtDgCwZYv2FYVk0ABw6F6CWbuZLUVykks69AG0xasti7Xjh3AximUnZLefs
iuJqg2KpRzfv1CM+Cw5cp2GmIVvRqq0GlRZGxJ38AqH9oyUa2m3TojxWapY47zye
PYEjWwRTGlxUBkdujdcYj6/dojNkm4azsDXl9W5YaXiPfbgJAkEA4rlhSPXlohDk
FoyfX0v2OIdaTOcVpinv1jjbSzZ8KZACggjiNUVrSFV3Y4oWom93K5JLXf2mV0Sy
80mPR5jOdwJBAMwciAk8xyQKpMUGNhFX2jKboAYY1SJCfuUnyXHAPWeHp5xCL2UH
tjryJp/Vx8TgsFTGyWSyIE9R8hSup+32rkcCQBe+EAkC7yQ0np4Z5cql+sfarMMm
4+Z9t8b4N0a+EuyLTyfs5Dtt5JkzkggTeuFRyOoALPJP0K6M3CyMBHwb7WsCQQCi
TM2fCsUO06fRQu8bO1A1janhLz3K0DU24jw8RzCMckHE7pvhKhCtLn+n+MWwtzl/
L9JUT4+BgxeLepXtkolhAkEA2V7er7fnEuL0+kKIjmOm5F3kvMIDh9YC1JwLGSvu
1fnzxK34QwSdxgQRF1dfIKJw73lClQpHZfQxL/2XRG8IoA==";

            var encResult = CryptoHelper.RSAEncrypt(rawText, _publicKey);
            Assert.True(encResult.Success);

            var decResult = CryptoHelper.RSADecrypt(encResult.Value, _privateKey);
            Assert.True(decResult.Success);

            Assert.Equal(rawText, decResult.Value);
        }
    }
}
