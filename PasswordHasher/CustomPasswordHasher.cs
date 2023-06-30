using System.Security.Cryptography;
using System.Text;

namespace PasswordHasher.Sha256;

internal class CustomPasswordHasher : IPasswordHasher
{
    private const int SaltSize = 16;
    private const int HashSize = 32;
    private const int Iterations = 10000;

    public string HashPassword(string password)
    {
        // ایجاد رمز تصادفی برای نمک
        byte[] salt;
        new RNGCryptoServiceProvider().GetBytes(salt = new byte[SaltSize]);

        // انجام رمزنگاری هش بر روی پسورد
        var pbkdf2 = new Rfc2898DeriveBytes(password, salt, Iterations);
        byte[] hash = pbkdf2.GetBytes(HashSize);

        // ترکیب نمک و رمزنگاری هش شده و تبدیل به رشته
        byte[] hashBytes = new byte[SaltSize + HashSize];
        Array.Copy(salt, 0, hashBytes, 0, SaltSize);
        Array.Copy(hash, 0, hashBytes, SaltSize, HashSize);

        return Convert.ToBase64String(hashBytes);
    }

    public bool VerifyHashedPassword(string password, string hashedPassword)
    {
        // تبدیل رشته رمزنگاری شده به بایت‌ها
        byte[] hashBytes = Convert.FromBase64String(hashedPassword);

        // استخراج نمک از رشته رمزنگاری شده
        byte[] salt = new byte[SaltSize];
        Array.Copy(hashBytes, 0, salt, 0, SaltSize);

        // انجام رمزنگاری هش بر روی پسورد و مقایسه نتیجه با رشته رمزنگاری شده اصلی
        var pbkdf2 = new Rfc2898DeriveBytes(password, salt, Iterations);
        byte[] hash = pbkdf2.GetBytes(HashSize);

        for (int i = 0; i < HashSize; i++)
        {
            if (hashBytes[i + SaltSize] != hash[i])
                return false;
        }

        return true;
    }
}
