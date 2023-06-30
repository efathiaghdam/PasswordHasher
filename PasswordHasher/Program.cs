
using Microsoft.Extensions.DependencyInjection;
using PasswordHasher.Sha256;

var services = new ServiceCollection();
services.AddSingleton<IPasswordHasher, CustomPasswordHasher>();
services.AddSingleton<PasswordHasherCheck>();

var serviceProvider = services.BuildServiceProvider();

var checker = serviceProvider.GetService<PasswordHasherCheck>();

string password = "1qaz4rfv9ol.)P:?";
string hashedPassword = checker.SetHashPassword(password);

checker.VerifyPassword(password, hashedPassword);

Console.ReadLine();