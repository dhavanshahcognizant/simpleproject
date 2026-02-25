using Microsoft.AspNetCore.Mvc;
using System.Diagnostics;
using System.Text;

namespace VulnerableApp.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class ConfigController : ControllerBase
    {
        // VULNERABILITY: Hardcoded API Keys and Credentials
        private const string API_KEY = "sk-9876543210abcdefghijk";
        private const string DATABASE_PASSWORD = "admin123";
        private const string AWS_SECRET = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";

        // VULNERABILITY: Environment variables exposed
        [HttpGet("settings")]
        public IActionResult GetSettings()
        {
            // VULNERABILITY: Exposing all configuration
            return Ok(new
            {
                ApiKey = API_KEY,
                DatabasePassword = DATABASE_PASSWORD,
                AwsSecret = AWS_SECRET,
                ConnectionString = "Data Source=vulnerable.db",
                Environment = System.Environment.GetEnvironmentVariables()
            });
        }

        // VULNERABILITY: Command Injection via Process execution
        [HttpGet("execute")]
        public IActionResult ExecuteCommand(string cmd)
        {
            try
            {
                // CRITICAL: Command injection vulnerability
                var process = new ProcessStartInfo
                {
                    FileName = "cmd.exe",
                    Arguments = $"/c {cmd}", // Unsanitized user input
                    RedirectStandardOutput = true,
                    UseShellExecute = false
                };

                using (var proc = Process.Start(process))
                {
                    var output = proc.StandardOutput.ReadToEnd();
                    return Ok(new { output = output });
                }
            }
            catch (Exception ex)
            {
                return BadRequest($"Error: {ex.Message}");
            }
        }

        // VULNERABILITY: LDAP Injection
        [HttpGet("auth-ldap")]
        public IActionResult AuthenticateLdap(string username, string password)
        {
            // VULNERABILITY: LDAP Injection - filters not escaped
            string ldapFilter = $"(&(uid={username})(userPassword={password}))";
            
            // In real app, would execute LDAP query
            // Attacker could use: *) + (|(uid=* to bypass authentication
            
            return Ok($"LDAP Filter: {ldapFilter}");
        }

        // VULNERABILITY: XML External Entity (XXE) Injection
        [HttpPost("parse-xml")]
        public IActionResult ParseXml([FromBody] string xmlContent)
        {
            try
            {
                // VULNERABILITY: XXE - Unsafe XML parsing
                var xmlDoc = new System.Xml.XmlDocument();
                // Should disable DTD, but it's not:
                xmlDoc.LoadXml(xmlContent);
                
                // Attacker could submit:
                // <?xml version="1.0"?>
                // <!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
                // <data>&xxe;</data>

                return Ok("XML parsed");
            }
            catch (Exception ex)
            {
                return BadRequest($"Error: {ex.Message}");
            }
        }

        // VULNERABILITY: Broken Crypto - Weak Encryption
        [HttpPost("encrypt")]
        public IActionResult EncryptData([FromBody] string data)
        {
            // VULNERABILITY: Using weak encryption method
            var key = "WeakKeyValue1234"; // Fixed, predictable key
            var encrypted = EncryptString(data, key);
            return Ok(new { encrypted = encrypted });
        }

        // VULNERABILITY: Insufficient Randomness
        private string EncryptString(string plaintext, string key)
        {
            // VULNERABILITY: No IV, predictable encryption
            var keyBytes = Encoding.UTF8.GetBytes(key);
            var plaintextBytes = Encoding.UTF8.GetBytes(plaintext);
            
            // Simple XOR cipher - extremely weak
            var encrypted = new byte[plaintextBytes.Length];
            for (int i = 0; i < plaintextBytes.Length; i++)
            {
                encrypted[i] = (byte)(plaintextBytes[i] ^ keyBytes[i % keyBytes.Length]);
            }

            return Convert.ToBase64String(encrypted);
        }

        // VULNERABILITY: Weak Token Generation
        [HttpPost("generate-token")]
        public IActionResult GenerateToken(string userId)
        {
            // VULNERABILITY: Weak random token
            var random = new Random(); // Not cryptographically secure
            var token = random.Next().ToString();
            
            return Ok(new { Token = token, UserId = userId });
        }

        // VULNERABILITY: Insecure Session Management
        [HttpGet("session-info")]
        public IActionResult GetSessionInfo()
        {
            var sessionId = HttpContext.Session.Id;
            
            // VULNERABILITY: Session ID might be predictable
            // VULNERABILITY: No HTTPS-only flag on session cookies
            return Ok(new { SessionId = sessionId });
        }

        // VULNERABILITY: Information Disclosure - Source Code
        [HttpGet("source-code")]
        public IActionResult GetSourceCode(string filename)
        {
            // VULNERABILITY: Could expose application source code
            try
            {
                var path = Path.Combine(Directory.GetCurrentDirectory(), filename);
                var content = System.IO.File.ReadAllText(path);
                return Ok(new { content = content });
            }
            catch
            {
                return NotFound();
            }
        }
    }
}
