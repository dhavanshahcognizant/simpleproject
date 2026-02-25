using Microsoft.AspNetCore.Mvc;
using VulnerableApp.Data;
using VulnerableApp.Models;

namespace VulnerableApp.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class OrderController : ControllerBase
    {
        private readonly VulnerableDbContext _dbContext;

        public OrderController(VulnerableDbContext dbContext)
        {
            _dbContext = dbContext;
        }

        // VULNERABILITY: Insecure Direct Object Reference (IDOR) - Price Manipulation
        [HttpPost("create")]
        public IActionResult CreateOrder([FromBody] OrderRequest request)
        {
            // VULNERABILITY: Trusting client-provided price instead of calculating server-side
            var product = _dbContext.Products.FirstOrDefault(p => p.Id == request.ProductId);
            
            if (product == null)
                return NotFound();

            // CRITICAL: Client can set any price! Should use product.Price from database
            var order = new Order
            {
                UserId = request.UserId,
                OrderDate = DateTime.Now,
                TotalAmount = request.TotalAmount, // VULNERABILITY: Trusting client input
                Status = "Pending",
                PaymentMethod = request.PaymentMethod,
                TransactionId = request.TransactionId
            };

            _dbContext.Orders.Add(order);
            _dbContext.SaveChanges();

            return Ok(new { OrderId = order.Id, Amount = order.TotalAmount });
        }

        // VULNERABILITY: Insufficient Authorization
        [HttpPut("{orderId}/update-price")]
        public IActionResult UpdateOrderPrice(int orderId, decimal newPrice)
        {
            // No authorization - anyone can modify any order price
            var order = _dbContext.Orders.FirstOrDefault(o => o.Id == orderId);
            
            if (order == null)
                return NotFound();

            // VULNERABILITY: No authorization check, directly updating price
            order.TotalAmount = newPrice;
            _dbContext.SaveChanges();

            return Ok("Order price updated");
        }

        // VULNERABILITY: Logic Bypass - Negative Amount
        [HttpPost("refund")]
        public IActionResult ProcessRefund(int orderId)
        {
            var order = _dbContext.Orders.FirstOrDefault(o => o.Id == orderId);
            
            if (order == null)
                return NotFound();

            // VULNERABILITY: No validation on refund amount
            order.TotalAmount = -order.TotalAmount; // Could manipulate account balance
            order.Status = "Refunded";
            _dbContext.SaveChanges();

            return Ok("Refund processed");
        }

        // VULNERABILITY: Broken Business Logic - Double Charging
        [HttpPost("charge")]
        public IActionResult ChargeCard(int orderId)
        {
            var order = _dbContext.Orders.FirstOrDefault(o => o.Id == orderId);
            
            if (order == null)
                return NotFound();

            // VULNERABILITY: No idempotency check - could charge multiple times
            // VULNERABILITY: No transaction ID verification
            ProcessPayment(order.TotalAmount, order.PaymentMethod);
            
            order.Status = "Paid";
            _dbContext.SaveChanges();

            return Ok("Payment processed");
        }

        private void ProcessPayment(decimal amount, string method)
        {
            // Simulated payment processing
            // In reality, integrates with payment gateway
        }

        // VULNERABILITY: Information Disclosure - Payment Details
        [HttpGet("{orderId}")]
        public IActionResult GetOrder(int orderId)
        {
            var order = _dbContext.Orders.FirstOrDefault(o => o.Id == orderId);
            
            if (order == null)
                return NotFound();

            // VULNERABILITY: Returning sensitive payment information
            return Ok(new
            {
                order.Id,
                order.UserId,
                order.OrderDate,
                order.TotalAmount,
                order.Status,
                order.PaymentMethod, // Sensitive
                order.TransactionId   // Sensitive
            });
        }
    }

    public class OrderRequest
    {
        public int ProductId { get; set; }
        public int UserId { get; set; }
        // VULNERABILITY: Client provides price
        public decimal TotalAmount { get; set; }
        public string PaymentMethod { get; set; }
        public string TransactionId { get; set; }
    }
}
