namespace PasswordHasher.Sha256;

internal class PasswordHasherCheck
{
    private readonly IPasswordHasher _passwordHasher;

    public PasswordHasherCheck(IPasswordHasher passwordHasher)
    {
        _passwordHasher = passwordHasher;
    }

    public string  SetHashPassword(string password)
    {
        string hashedPassword = _passwordHasher.HashPassword(password);

        Console.WriteLine(hashedPassword);

        return hashedPassword;
    }

    public void VerifyPassword(string password,string hashedPassword)
    {
        bool isValid = _passwordHasher.VerifyHashedPassword(password, hashedPassword);

        Console.WriteLine(isValid);
    }
}
