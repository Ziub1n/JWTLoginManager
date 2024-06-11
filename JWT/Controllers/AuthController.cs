using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.ComponentModel.DataAnnotations;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;

namespace JWT.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        private static List<User> Users = new List<User>();
        private static Dictionary<string, string> RefreshTokens = new Dictionary<string, string>();

        [HttpPost("login")]
        public IActionResult Login([FromBody] LoginRequestModel loginRequest)
        {
            var user = Users.FirstOrDefault(u => u.Name == loginRequest.UserName);
            if (user == null)
            {
                Console.WriteLine("Invalid username");
                return Unauthorized("Invalid login or password");
            }

            var passwordHasher = new PasswordHasher<User>();
            var result = passwordHasher.VerifyHashedPassword(user, user.Password, loginRequest.Password);

            if (result != PasswordVerificationResult.Success)
            {
                Console.WriteLine("Invalid password");
                return Unauthorized("Invalid login or password");
            }

            var token = GenerateJwtToken(user.Name);
            var refreshToken = GenerateRefreshToken();
            RefreshTokens[refreshToken] = user.Name;

            Console.WriteLine($"User {loginRequest.UserName} logged in successfully");
            return Ok(new LoginResponseModel { Token = token, RefreshToken = refreshToken });
        }



        [HttpPost("refresh")]
        public IActionResult Refresh([FromBody] RefreshTokenRequestModel refreshTokenRequest)
        {
            if (!RefreshTokens.TryGetValue(refreshTokenRequest.RefreshToken, out var userName))
                return Unauthorized("Invalid token");

            var token = GenerateJwtToken(userName);
            var newRefreshToken = GenerateRefreshToken();
            RefreshTokens[newRefreshToken] = userName;
            RefreshTokens.Remove(refreshTokenRequest.RefreshToken);

            return Ok(new LoginResponseModel { Token = token, RefreshToken = newRefreshToken });
        }

        [HttpPost("register")]
        public IActionResult Register([FromBody] RegisterRequestModel registerRequest)
        {
            if (Users.Any(u => u.Name == registerRequest.UserName))
            {
                Console.WriteLine("Username already exists");
                return BadRequest("Username already exists");
            }

            var passwordHasher = new PasswordHasher<User>();
            var hashedPassword = passwordHasher.HashPassword(new User(), registerRequest.Password);

            Users.Add(new User { Name = registerRequest.UserName, Password = hashedPassword });
            Console.WriteLine($"User {registerRequest.UserName} registered with password hash: {hashedPassword}");
            return Ok();
        }



        private string GenerateJwtToken(string userName)
        {
            var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes("dd3irifsndasdajskndfdd3irifsndasdajskndfdd3irifsndasdajskndfdd3irifsndasdajskndfh")); // Klucz powinien być taki sam
            var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);

            var token = new JwtSecurityToken(
                issuer: "KO-Tokens",
                audience: "http://localhost:5022",
                claims: new[] { new Claim(ClaimTypes.Name, userName) },
                expires: DateTime.Now.AddMinutes(30),
                signingCredentials: credentials);

            return new JwtSecurityTokenHandler().WriteToken(token);
        }


        private string GenerateRefreshToken()
        {
            var randomNumber = new byte[32];
            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(randomNumber);
                return Convert.ToBase64String(randomNumber);
            }
        }
    }

    public class RefreshTokenRequestModel
    {
        public string RefreshToken { get; set; } = null!;
    }

    public class RegisterRequestModel
    {
        [Required]
        public string UserName { get; set; } = null!;
        [Required]
        public string Password { get; set; } = null!;
    }

    public class LoginRequestModel
    {
        [Required]
        public string UserName { get; set; } = null!;
        [Required]
        public string Password { get; set; } = null!;
    }

    public class LoginResponseModel
    {
        public string Token { get; set; } = null!;
        public string RefreshToken { get; set; } = null!;
    }

    public class User
    {
        public string Name { get; set; } = null!;
        public string Password { get; set; } = null!;
    }
}
