using Microsoft.AspNetCore.Mvc;
using Microsoft.Data.Sqlite;
using VulnerableApp.Data;
using VulnerableApp.Models;
using Newtonsoft.Json;

namespace VulnerableApp.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class ProductController : ControllerBase
    {
        private readonly VulnerableDbContext _dbContext;
        private readonly IConfiguration _configuration;

        public ProductController(VulnerableDbContext dbContext, IConfiguration configuration)
        {
            _dbContext = dbContext;
            _configuration = configuration;
        }

        // VULNERABILITY: SQL Injection through price range
        [HttpGet("filter")]
        public IActionResult FilterProducts(string minPrice, string maxPrice)
        {
            try
            {
                // CRITICAL: SQL Injection vulnerability
                string query = $"SELECT * FROM Products WHERE Price >= {minPrice} AND Price <= {maxPrice}";
                var connectionString = _configuration.GetConnectionString("DefaultConnection") ?? "Data Source=vulnerable.db";
                var connection = new SqliteConnection(connectionString);
                connection.Open();
                var command = connection.CreateCommand();
                command.CommandText = query;
                var reader = command.ExecuteReader();
                
                var products = new List<Product>();
                while (reader.Read())
                {
                    products.Add(new Product
                    {
                        Id = (int)reader["Id"],
                        Name = reader["Name"]?.ToString() ?? "",
                        Description = reader["Description"]?.ToString() ?? "",
                        Price = (decimal)reader["Price"],
                        Stock = (int)reader["Stock"]
                    });
                }
                connection.Close();
                return Ok(products);
            }
            catch (Exception ex)
            {
                return BadRequest($"Error: {ex.Message}");
            }
        }

        // VULNERABILITY: Insecure Deserialization
        [HttpPost("create")]
        public IActionResult CreateProduct([FromBody] string jsonData)
        {
            try
            {
                // VULNERABILITY: Deserializing untrusted input without validation
                // Using TypeNameHandling which is dangerous
                var settings = new JsonSerializerSettings
                {
                    TypeNameHandling = TypeNameHandling.All // DANGEROUS!
                };
                
                var product = JsonConvert.DeserializeObject<Product>(jsonData, settings);
                
                if (product == null)
                {
                    return BadRequest("Invalid product data");
                }

                // VULNERABILITY: No authorization check
                product.CreatedDate = DateTime.Now;
                _dbContext.Products.Add(product);
                _dbContext.SaveChanges();

                return Ok(new { message = "Product created", id = product.Id });
            }
            catch (Exception ex)
            {
                // VULNERABILITY: Exposing stack trace
                return BadRequest($"Deserialization error: {ex.StackTrace}");
            }
        }

        // VULNERABILITY: Unvalidated quantity could cause integer overflow
        [HttpPost("bulk-update")]
        public IActionResult BulkUpdateStock(int quantity)
        {
            // VULNERABILITY: No integer overflow check
            // quantity can be negative causing stock issues
            var products = _dbContext.Products.ToList();
            foreach (var product in products)
            {
                product.Stock += quantity; // Could go negative
            }
            _dbContext.SaveChanges();
            return Ok("Stocks updated");
        }

        // VULNERABILITY: Path Traversal in file download
        [HttpGet("download")]
        public IActionResult DownloadProductFile(string filename)
        {
            // VULNERABILITY: No path validation - could access any file
            string basePath = Directory.GetCurrentDirectory();
            string fullPath = Path.Combine(basePath, filename);

            // Attacker could use: ../../../etc/passwd or ../../windows/win.ini
            if (System.IO.File.Exists(fullPath))
            {
                var file = System.IO.File.ReadAllBytes(fullPath);
                return File(file, "application/octet-stream", Path.GetFileName(fullPath));
            }
            return NotFound();
        }

        // VULNERABILITY: Race condition in stock check
        [HttpPost("purchase")]
        public IActionResult PurchaseProduct(int productId, int quantity)
        {
            var product = _dbContext.Products.FirstOrDefault(p => p.Id == productId);
            
            if (product == null)
                return NotFound();

            // VULNERABILITY: Race condition - stock could be purchased concurrently
            if (product.Stock >= quantity)
            {
                product.Stock -= quantity;
                _dbContext.SaveChanges();
                return Ok("Purchase successful");
            }

            return BadRequest("Insufficient stock");
        }

        // VULNERABILITY: No input size limit - potential DoS
        [HttpPost("add-description")]
        public IActionResult AddDescription(int productId, [FromBody] string description)
        {
            var product = _dbContext.Products.FirstOrDefault(p => p.Id == productId);
            if (product == null)
                return NotFound();

            // VULNERABILITY: No size limit, could cause memory exhaustion
            product.Description += description;
            _dbContext.SaveChanges();
            return Ok("Description updated");
        }
    }
}
