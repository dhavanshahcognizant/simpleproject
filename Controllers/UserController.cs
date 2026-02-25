using Microsoft.AspNetCore.Mvc;
using Microsoft.Data.Sqlite;
using VulnerableApp.Data;
using VulnerableApp.Models;

namespace VulnerableApp.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class UserController : ControllerBase
    {
        private readonly VulnerableDbContext _dbContext;
        private readonly IConfiguration _configuration;

        public UserController(VulnerableDbContext dbContext, IConfiguration configuration)
        {
            _dbContext = dbContext;
            _configuration = configuration;
        }

        // VULNERABILITY: SQL Injection - Direct string concatenation
        [HttpGet("search")]
        public IActionResult SearchUsers(string username)
        {
            try
            {
                // CRITICAL: SQL Injection vulnerability
                string query = $"SELECT * FROM Users WHERE Username = '{username}'";
                var connectionString = _configuration.GetConnectionString("DefaultConnection") ?? "Data Source=vulnerable.db";
                var connection = new SqliteConnection(connectionString);
                connection.Open();
                var command = connection.CreateCommand();
                command.CommandText = query;
                var reader = command.ExecuteReader();
                
                var users = new List<User>();
                while (reader.Read())
                {
                    users.Add(new User
                    {
                        Id = (int)reader["Id"],
                        Username = reader["Username"]?.ToString() ?? "",
                        Email = reader["Email"]?.ToString() ?? "",
                        Password = reader["Password"]?.ToString() ?? "" // VULNERABILITY: Exposing password
                    });
                }
                connection.Close();
                return Ok(users);
            }
            catch (Exception ex)
            {
                // VULNERABILITY: Exposing sensitive error information
                return BadRequest($"Database error: {ex.Message}");
            }
        }

        // VULNERABILITY: Weak Authentication
        [HttpPost("login")]
        public IActionResult Login([FromBody] LoginRequest request)
        {
            // VULNERABILITY: No rate limiting, no account lockout
            // VULNERABILITY: Plaintext password comparison
            var user = _dbContext.Users.FirstOrDefault(u => u.Username == request.Username && u.Password == request.Password);
            
            if (user == null)
            {
                return Unauthorized("Invalid credentials");
            }

            // VULNERABILITY: Returning sensitive information
            return Ok(new
            {
                user.Id,
                user.Username,
                user.Email,
                user.Password,
                user.CreditCardNumber,
                user.SocialSecurityNumber,
                Token = "fake-jwt-token-" + user.Id // VULNERABILITY: Insecure token generation
            });
        }

        // VULNERABILITY: Insecure Direct Object Reference (IDOR)
        [HttpGet("{id}")]
        public IActionResult GetUser(int id)
        {
            // No authorization check - anyone can get any user's data
            var user = _dbContext.Users.FirstOrDefault(u => u.Id == id);
            if (user == null)
            {
                return NotFound();
            }

            // VULNERABILITY: Exposing all sensitive data
            return Ok(new
            {
                user.Id,
                user.Username,
                user.Email,
                user.Password,
                user.ApiKey,
                user.CreditCardNumber,
                user.SocialSecurityNumber,
                user.IsAdmin
            });
        }

        // VULNERABILITY: Path Traversal in file parameter
        [HttpGet("export")]
        public IActionResult ExportUserData(string format)
        {
            // VULNERABILITY: No input validation on format
            string filePath = $"/exports/{format}";
            
            // This could be exploited with: ../../sensitive/file.txt
            if (System.IO.File.Exists(filePath))
            {
                var file = System.IO.File.ReadAllBytes(filePath);
                return File(file, "application/octet-stream", Path.GetFileName(filePath));
            }
            return NotFound();
        }

        // VULNERABILITY: Unvalidated Redirect
        [HttpGet("redirect-to")]
        public IActionResult RedirectTo(string url)
        {
            // VULNERABILITY: No validation of redirect URL
            // Could redirect to malicious site
            return Redirect(url);
        }

        // VULNERABILITY: Command Injection
        [HttpGet("generate-report")]
        public IActionResult GenerateReport(string reportType)
        {
            try
            {
                // CRITICAL: Command injection vulnerability
                var process = new System.Diagnostics.ProcessStartInfo()
                {
                    FileName = "cmd.exe",
                    Arguments = $"/c echo {reportType} > report.txt", // Vulnerable to command injection
                    RedirectStandardOutput = true,
                    UseShellExecute = false
                };
                
                var proc = System.Diagnostics.Process.Start(process);
                proc?.WaitForExit();
                return Ok("Report generated");
            }
            catch (Exception ex)
            {
                return BadRequest(ex.Message);
            }
        }
    }

    public class LoginRequest
    {
        public string? Username { get; set; }
        public string? Password { get; set; }
    }
}
