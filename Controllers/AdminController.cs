using Microsoft.AspNetCore.Mvc;
using Microsoft.Data.Sqlite;
using VulnerableApp.Data;
using VulnerableApp.Models;

namespace VulnerableApp.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class AdminController : ControllerBase
    {
        private readonly VulnerableDbContext _dbContext;
        private readonly IConfiguration _configuration;

        public AdminController(VulnerableDbContext dbContext, IConfiguration configuration)
        {
            _dbContext = dbContext;
            _configuration = configuration;
        }

        // VULNERABILITY: Missing authentication/authorization
        [HttpGet("all-users")]
        public IActionResult GetAllUsers()
        {
            // No authentication check - should require admin role
            var users = _dbContext.Users.Select(u => new
            {
                u.Id,
                u.Username,
                u.Email,
                u.Password,
                u.ApiKey,
                u.CreditCardNumber,
                u.SocialSecurityNumber,
                u.IsAdmin
            }).ToList();

            return Ok(users);
        }

        // VULNERABILITY: Privilege Escalation
        [HttpPost("promote-user")]
        public IActionResult PromoteUser(int userId)
        {
            // No authorization check - anyone can promote users
            var user = _dbContext.Users.FirstOrDefault(u => u.Id == userId);
            
            if (user == null)
                return NotFound();

            user.IsAdmin = true; // Dangerous - no verification of requester's role
            _dbContext.SaveChanges();

            return Ok("User promoted to admin");
        }

        // VULNERABILITY: Information Disclosure through debug endpoint
        [HttpGet("debug-info")]
        public IActionResult DebugInfo()
        {
            // Should never expose this in production
            var dbPath = _configuration.GetConnectionString("DefaultConnection");
            var totalUsers = _dbContext.Users.Count();
            var totalProducts = _dbContext.Products.Count();

            return Ok(new
            {
                DatabasePath = dbPath,
                TotalUsers = totalUsers,
                TotalProducts = totalProducts,
                Environment = "Production", // Should be checked
                DotNetVersion = System.Runtime.InteropServices.RuntimeInformation.FrameworkDescription,
                MachineName = System.Environment.MachineName,
                UserName = System.Environment.UserName
            });
        }

        // VULNERABILITY: SQL Injection in order reports
        [HttpGet("order-report")]
        public IActionResult GenerateOrderReport(string userId, string startDate, string endDate)
        {
            try
            {
                // CRITICAL: SQL Injection vulnerability
                string query = $@"
                    SELECT * FROM Orders 
                    WHERE UserId = {userId} 
                    AND OrderDate >= '{startDate}' 
                    AND OrderDate <= '{endDate}'";
                
                var connectionString = _configuration.GetConnectionString("DefaultConnection") ?? "Data Source=vulnerable.db";
                var connection = new SqliteConnection(connectionString);
                connection.Open();
                var command = connection.CreateCommand();
                command.CommandText = query;
                
                var report = new List<dynamic>();
                var reader = command.ExecuteReader();
                
                while (reader.Read())
                {
                    report.Add(new
                    {
                        Id = reader["Id"],
                        TotalAmount = reader["TotalAmount"],
                        TransactionId = reader["TransactionId"] // VULNERABILITY: Exposing transaction IDs
                    });
                }
                
                connection.Close();
                return Ok(report);
            }
            catch (Exception ex)
            {
                // VULNERABILITY: Exposing detailed error information
                return BadRequest(new { error = ex.Message, stackTrace = ex.StackTrace });
            }
        }

        // VULNERABILITY: Weak CSRF protection
        [HttpPost("reset-database")]
        public IActionResult ResetDatabase()
        {
            // No CSRF token validation
            // No confirmation, no additional verification
            try
            {
                _dbContext.Users.RemoveRange(_dbContext.Users);
                _dbContext.Products.RemoveRange(_dbContext.Products);
                _dbContext.Orders.RemoveRange(_dbContext.Orders);
                _dbContext.Comments.RemoveRange(_dbContext.Comments);
                _dbContext.SaveChanges();
                
                return Ok("Database reset successfully");
            }
            catch (Exception ex)
            {
                return BadRequest($"Error: {ex.Message}");
            }
        }

        // VULNERABILITY: Mass Assignment - accepting all fields without validation
        [HttpPost("create-admin-user")]
        public IActionResult CreateAdminUser([FromBody] dynamic userData)
        {
            // VULNERABILITY: Directly binding user input to model
            // Could bypass authorization checks if properties are set
            try
            {
                var user = new User
                {
                    Username = userData.Username,
                    Password = userData.Password,
                    Email = userData.Email,
                    IsAdmin = true, // VULNERABILITY: Always creates admin
                    ApiKey = userData.ApiKey,
                    CreditCardNumber = userData.CreditCardNumber,
                    SocialSecurityNumber = userData.SocialSecurityNumber,
                    CreatedDate = DateTime.Now
                };

                _dbContext.Users.Add(user);
                _dbContext.SaveChanges();

                return Ok(new { message = "Admin user created", id = user.Id });
            }
            catch (Exception ex)
            {
                return BadRequest(ex.Message);
            }
        }

        // VULNERABILITY: Hardcoded backdoor function
        [HttpGet("backdoor")]
        public IActionResult Backdoor(string command)
        {
            // CRITICAL: Hardcoded backdoor access
            if (command == "get-all-passwords")
            {
                var passwords = _dbContext.Users.Select(u => new
                {
                    u.Username,
                    u.Password
                }).ToList();

                return Ok(passwords);
            }
            else if (command == "execute-sql")
            {
                // CRITICAL: Execute arbitrary SQL
                return Ok("SQL Execution allowed");
            }

            return BadRequest("Unknown command");
        }
    }
}
