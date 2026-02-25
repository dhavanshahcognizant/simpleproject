namespace VulnerableApp.Models
{
    public class User
    {
        public int Id { get; set; }
        public string Username { get; set; }
        // VULNERABILITY: Plaintext password storage
        public string Password { get; set; }
        public string Email { get; set; }
        public string? ApiKey { get; set; }
        public DateTime CreatedDate { get; set; }
        public bool IsAdmin { get; set; }
        // VULNERABILITY: Storing sensitive data
        public string? CreditCardNumber { get; set; }
        public string? SocialSecurityNumber { get; set; }
    }
}
