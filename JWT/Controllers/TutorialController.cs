using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using System.ComponentModel.DataAnnotations;
using System.Security.Cryptography;
using System.Text;

namespace JWT.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class TutorialController : ControllerBase
    {
        //Generated password does not work with /verify-password endpoint!
        [HttpGet("hash-password/{password}")]
        public IActionResult HashPassword(string password)
        {
            Console.WriteLine("hash-password");

            var hash = Rfc2898DeriveBytes.Pbkdf2(
                Encoding.UTF8.GetBytes(password),
                new byte[] {0},
                10,
                HashAlgorithmName.SHA512,
                1
            );

            return Ok(Convert.ToHexString(hash));
        }

        [HttpGet("hash-password-with-salt/{password}")]
        public IActionResult HashPasswordWithSalt(string password)
        {
            var passwordHasher = new PasswordHasher<User>();
            return Ok(passwordHasher.HashPassword(new User(), password));
        }

        [HttpPost("verify-password")]
        public IActionResult VerifyPassword(VerifyPasswordRequestModel requestModel)
        {
            var passwordHasher = new PasswordHasher<User>();
            return Ok(passwordHasher.VerifyHashedPassword(new User(), requestModel.Hash, requestModel.Password) == PasswordVerificationResult.Success);
        }

        // Zabezpieczona końcówka
        [HttpGet("secure-endpoint")]
        [Authorize]
        public IActionResult SecureEndpoint()
        {
            return Ok("This is a secure endpoint");
        }
    }

    public class VerifyPasswordRequestModel
    {
        public string Password { get; set; } = null!;
        public string Hash { get; set; } = null!;
    }
}