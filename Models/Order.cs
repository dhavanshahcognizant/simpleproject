namespace VulnerableApp.Models
{
    public class Order
    {
        public int Id { get; set; }
        public int UserId { get; set; }
        public DateTime OrderDate { get; set; }
        public decimal TotalAmount { get; set; }
        public string Status { get; set; }
        // VULNERABILITY: Storing sensitive payment information
        public string? PaymentMethod { get; set; }
        public string? TransactionId { get; set; }
    }
}
