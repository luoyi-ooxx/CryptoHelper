using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

public class CryptoHelper
{
    private byte[] byteSALT;

    public CryptoHelper(string salt) 
    {
        byteSALT = Encoding.UTF8.GetBytes(salt);
    }

    public string GenerateSHA(string input) 
    {
        using (SHA1 sha1 = new SHA1CryptoServiceProvider()) {
            byte[] hashBytes = sha1.ComputeHash(SaltFactory(input));

            // 將 Hash 轉換成 16 進位字串
            StringBuilder sb = new StringBuilder();
            foreach (byte b in hashBytes) {
                sb.Append(b.ToString("x2"));
            }
            return sb.ToString();
        }
    }

    public string GenerateSHA256(string input) 
    {
        using (SHA256 sha256 = SHA256.Create()) {
            byte[] hashBytes = sha256.ComputeHash(SaltFactory(input)); 

            // 將 Hash 轉換成 16 進位字串
            StringBuilder sb = new StringBuilder();
            foreach (byte b in hashBytes) {
                sb.Append(b.ToString("x2"));
            }
            return sb.ToString();
        }
    }


    public string GenerateMdCode(string input) // generateMD5
    {
        using (MD5 md5 = MD5.Create()) {
            byte[] hashBytes = md5.ComputeHash(SaltFactory(input));    // 計算 MD5 雜湊值

            // 將 byte[] 轉換為 16 進位字串
            StringBuilder sb = new StringBuilder();
            foreach (byte b in hashBytes) {
                sb.Append(b.ToString("x2")); // 轉為 16 進位格式
            }
            return sb.ToString();
        }
    }

    public string GeneratePbkdf2(string input) {
        using (var pbkdf2 = new Rfc2898DeriveBytes(input, byteSALT, 100_000, HashAlgorithmName.SHA256)) {
            return Convert.ToBase64String(pbkdf2.GetBytes(32));
        }
    }

    /*
    //dotnet add package BCrypt.Net-Next
    //using BCrypt.Net
    public string GenerateBCrypt(string input) {
        if (!string.IsNullOrEmpty(input)) {
            return BCrypt.Net.BCrypt.HashPassword(input);
        } else {
            throw new ArgumentNullException(nameof(input), "輸入不能為 null");
            //return null;
        }
    }

    public int VerifyBCrypt(string input, string dbVal) {
        if (!string.IsNullOrEmpty(input) && !string.IsNullOrEmpty(dbVal)) {
            bool isMatch = BCrypt.Net.BCrypt.Verify(input, dbVal);
            if (isMatch) {
                return 1; // 密碼正確
            } else {
                return -1; // 密碼錯誤
            }
        } else {
            throw new ArgumentNullException(nameof(input), "輸入不能為 null");
            //return -2; //輸入有誤
        }
    }
    */

    // using System.Security.Cryptography;
    // **設定 AES 金鑰與 IV（向量）**
    //private static readonly byte[] AesKey = Encoding.UTF8.GetBytes("12345678901234567890123456789012"); // 32 bytes
    //private static readonly byte[] AesIV = Encoding.UTF8.GetBytes("1234567890123456"); // 16 bytes
    public string AesEncrypt(string plainText, string pwd) 
    {
        using (System.Security.Cryptography.Aes aesAlg = System.Security.Cryptography.Aes.Create()) {
            char[] pwdSha = GenerateSHA256(pwd).ToCharArray();
            aesAlg.Key = Encoding.UTF8.GetBytes((new string(pwdSha)).Substring(0, 32));
            aesAlg.IV = Encoding.UTF8.GetBytes((new string(pwdSha)).Substring(32, 16));
            aesAlg.Mode = CipherMode.CBC;
            aesAlg.Padding = PaddingMode.PKCS7;
            Array.Clear(pwdSha, 0, pwdSha.Length);

            try {
                using (MemoryStream memoryStream = new MemoryStream()) {
                    using (CryptoStream cryptoStream = new CryptoStream(memoryStream, aesAlg.CreateEncryptor(), CryptoStreamMode.Write)) {
                        byte[] plainBytes = Encoding.UTF8.GetBytes(plainText);
                        cryptoStream.Write(plainBytes, 0, plainBytes.Length);
                        cryptoStream.FlushFinalBlock();
                        return Convert.ToBase64String(memoryStream.ToArray());
                    }
                }
            } catch (Exception) {
                throw;
            }
        }
    }

    // **AES 解密**
    public string AesDecrypt(string cipherText, string pwd)
    {
        using (System.Security.Cryptography.Aes aesAlg = System.Security.Cryptography.Aes.Create()) {
            try {
                char[] pwdSha = GenerateSHA256(pwd).ToCharArray();
                aesAlg.Key = Encoding.UTF8.GetBytes((new string(pwdSha)).Substring(0, 32));
                aesAlg.IV = Encoding.UTF8.GetBytes((new string(pwdSha)).Substring(32, 16));
                aesAlg.Mode = CipherMode.CBC;
                aesAlg.Padding = PaddingMode.PKCS7;
                Array.Clear(pwdSha, 0, pwdSha.Length);

                using (MemoryStream memoryStream = new MemoryStream(Convert.FromBase64String(cipherText)))
                using (CryptoStream cryptoStream = new CryptoStream(memoryStream, aesAlg.CreateDecryptor(), CryptoStreamMode.Read))
                using (StreamReader reader = new StreamReader(cryptoStream, Encoding.UTF8)) {
                    return reader.ReadToEnd();
                }
            } catch (System.FormatException) {
                throw;
            }
        }
    }

    private byte[] SaltFactory(string input) 
    {
        /*
        public static void BlockCopy (
            Array src,      // 來源陣列
            int srcOffset,  // 從來源陣列的哪個位元組位置開始複製
            Array dst,      // 目標陣列
            int dstOffset,  // 從目標陣列的哪個位元組位置開始貼上
            int count       // 要複製多少個位元組
        );
         */
        byte[] inputBytes = Encoding.UTF8.GetBytes(input);

        int inputLen = inputBytes.Length;
        int saltLen = byteSALT.Length;

        int maxPairCount = Math.Max((inputLen + 1) / 2, (saltLen + 1) / 2);
        int totalLength = inputLen + saltLen;

        byte[] mixed = new byte[totalLength];
        int inputIndex = 0, saltIndex = 0, mixedIndex = 0;

        for (int i = 0; i < maxPairCount; i++) {
            // 拷貝 input 的 2 bytes
            if (inputIndex < inputLen) {
                int count = Math.Min(2, inputLen - inputIndex);
                Buffer.BlockCopy(inputBytes, inputIndex, mixed, mixedIndex, count);
                inputIndex += count;
                mixedIndex += count;
            }

            // 拷貝 salt 的 2 bytes
            if (saltIndex < saltLen) {
                int count = Math.Min(2, saltLen - saltIndex);
                Buffer.BlockCopy(byteSALT, saltIndex, mixed, mixedIndex, count);
                saltIndex += count;
                mixedIndex += count;
            }
        }

        return mixed;
    }

    // -----------------------
}
