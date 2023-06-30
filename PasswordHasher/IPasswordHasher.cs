namespace PasswordHasher.Sha256;

internal interface IPasswordHasher
{
    string HashPassword(string password);
    bool VerifyHashedPassword(string password,string hashedPassword);
}
