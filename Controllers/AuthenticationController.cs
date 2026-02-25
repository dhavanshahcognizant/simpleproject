using Microsoft.AspNetCore.Mvc;
using System.Security.Cryptography;
using System.Text;

namespace VulnerableApp.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class AuthenticationController : ControllerBase
    {
        // VULNERABILITY: Hardcoded secrets and keys
        private const string HARDCODED_SECRET = "super-secret-key-12345";
        private const string JWT_SECRET = "my-secret-is-too-short-and-weak";

        // VULNERABILITY: Global static variable for authentication state
        private static string CurrentAuthToken = "";

        // VULNERABILITY: Weak Password Policy
        [HttpPost("register")]
        public IActionResult Register([FromBody] RegisterRequest request)
        {
            // VULNERABILITY: No password validation
            // VULNERABILITY: No email verification
            // VULNERABILITY: No duplicate user checks
            if (string.IsNullOrEmpty(request.Password))
            {
                return BadRequest("Password required");
            }

            // VULNERABILITY: Accepting any password
            // Should require: minimum length, complexity, etc.
            var user = new
            {
                Username = request.Username,
                Email = request.Email,
                Password = request.Password, // Stored plaintext
                RegisteredDate = DateTime.Now
            };

            return Ok(new { message = "User registered", userId = 999 });
        }

        // VULNERABILITY: Timing Attack Vulnerable Token Comparison
        [HttpPost("verify-token")]
        public IActionResult VerifyToken([FromBody] string token)
        {
            // VULNERABILITY: String comparison is timing attack vulnerable
            // Attacker can measure response time to guess characters
            if (token == HARDCODED_SECRET)
            {
                return Ok("Token is valid");
            }

            // Different response times for different length mismatches
            // Attacker can brute-force character by character
            return Unauthorized("Invalid token");
        }

        // VULNERABILITY: Weak PRNG for security tokens
        [HttpGet("generate-reset-token")]
        public IActionResult GenerateResetToken(int userId)
        {
            // VULNERABILITY: Using non-cryptographic Random
            var random = new Random();
            var token = random.Next(100000, 999999).ToString(); // 6-digit code
            
            // VULNERABILITY: Predictable tokens - can be brute-forced
            return Ok(new { ResetToken = token, UserId = userId });
        }

        // VULNERABILITY: JWT without signature verification
        [HttpPost("create-jwt")]
        public IActionResult CreateJwt([FromBody] string username)
        {
            // VULNERABILITY: Weak JWT implementation
            // VULNERABILITY: No expiration
            // VULNERABILITY: No signature algorithm specified
            
            var payload = Convert.ToBase64String(Encoding.UTF8.GetBytes(
                $"{{\"username\":\"{username}\", \"admin\":false}}"
            ));

            // VULNERABILITY: No signature - anyone can create valid JWTs
            var token = $"eyJhbGciOiJub25lIn0.{payload}.";
            
            return Ok(new { Token = token });
        }

        // VULNERABILITY: JWT with hardcoded secret, could be weak
        [HttpPost("validate-jwt")]
        public IActionResult ValidateJwt([FromBody] string token)
        {
            try
            {
                // VULNERABILITY: Minimal validation
                var parts = token.Split('.');
                if (parts.Length != 3)
                {
                    return Unauthorized("Invalid token format");
                }

                // VULNERABILITY: Not actually validating signature
                var payload = parts[1];
                var json = Encoding.UTF8.GetString(Convert.FromBase64String(payload));

                return Ok(new { Valid = true, Payload = json });
            }
            catch
            {
                return Unauthorized("Invalid token");
            }
        }

        // VULNERABILITY: Password Reset without verification
        [HttpPost("reset-password")]
        public IActionResult ResetPassword([FromBody] PasswordResetRequest request)
        {
            // VULNERABILITY: No token verification
            // VULNERABILITY: No user ownership check
            // VULNERABILITY: No email verification
            
            // Attacker could reset anyone's password with just the token
            return Ok("Password reset successful");
        }

        // VULNERABILITY: Two-Factor Authentication Bypass
        [HttpPost("verify-2fa")]
        public IActionResult Verify2FA([FromBody] string code)
        {
            // VULNERABILITY: No rate limiting on OTP attempts
            // VULNERABILITY: Can brute-force 6-digit codes (1 million combinations)
            // VULNERABILITY: OTP might not expire quickly
            
            if (code == "000000") // Hardcoded for testing
            {
                return Ok("2FA verified");
            }

            return Unauthorized("Invalid code");
        }

        // VULNERABILITY: Session Fixation
        [HttpGet("login-fixation")]
        public IActionResult LoginFixation(string sessionId)
        {
            // VULNERABILITY: Accepting caller-supplied session ID
            // Attacker can set a known session ID before login
            HttpContext.Session.SetString("SessionId", sessionId);
            return Ok("Session set");
        }

        // VULNERABILITY: Missing Secure Cookie Flags
        [HttpGet("set-auth-cookie")]
        public IActionResult SetAuthCookie(string username)
        {
            var authCookie = $"auth_{username}_{Guid.NewGuid()}";
            
            // VULNERABILITY: Not setting Secure flag (HTTPS only)
            // VULNERABILITY: Not setting HttpOnly flag (JS can't access)
            // VULNERABILITY: Not setting SameSite (CSRF vulnerable)
            Response.Cookies.Append("AuthToken", authCookie);
            
            return Ok("Cookie set");
        }

        // VULNERABILITY: Account Enumeration
        [HttpGet("user-exists")]
        public IActionResult CheckUserExists(string username)
        {
            // VULNERABILITY: Different responses for existing vs non-existing users
            // Attacker can enumerate valid usernames
            
            var existingUsers = new[] { "admin", "user1", "user2" };
            if (existingUsers.Contains(username))
            {
                return Ok(new { exists = true });
            }

            return NotFound(new { exists = false });
        }

        // VULNERABILITY: Password stored in URL
        [HttpGet("insecure-login")]
        public IActionResult InsecureLogin(string username, string password)
        {
            // VULNERABILITY: Password in URL
            // VULNERABILITY: Logged in server logs
            // VULNERABILITY: Visible in browser history
            // VULNERABILITY: Can be captured in HTTP proxies
            
            return Ok($"Logged in as {username}");
        }

        // VULNERABILITY: Weak Password Hashing
        [HttpPost("weak-hash-password")]
        public IActionResult WeakHashPassword(string password)
        {
            // VULNERABILITY: Using MD5 (broken)
            using (var md5 = MD5.Create())
            {
                var hash = md5.ComputeHash(Encoding.UTF8.GetBytes(password));
                var hashString = Convert.ToHexString(hash);
                return Ok(new { Hash = hashString });
            }
        }

        // VULNERABILITY: Hardcoded API Key in Header
        [HttpGet("check-api-key")]
        public IActionResult CheckApiKey()
        {
            var header = Request.Headers["X-API-Key"].ToString();
            
            // VULNERABILITY: Hardcoded API key in code
            if (header == "sk-9876543210abcdefghijk")
            {
                return Ok("API Key valid");
            }

            return Unauthorized("Invalid API Key");
        }
    }

    public class RegisterRequest
    {
        public string Username { get; set; }
        public string Email { get; set; }
        public string Password { get; set; }
    }

    public class PasswordResetRequest
    {
        public string Email { get; set; }
        public string Token { get; set; }
        public string NewPassword { get; set; }
    }
}
