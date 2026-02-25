using Microsoft.EntityFrameworkCore;
using VulnerableApp.Models;

namespace VulnerableApp.Data
{
    public class VulnerableDbContext : DbContext
    {
        public VulnerableDbContext(DbContextOptions<VulnerableDbContext> options) : base(options)
        {
        }

        public DbSet<User> Users { get; set; }
        public DbSet<Product> Products { get; set; }
        public DbSet<Comment> Comments { get; set; }
        public DbSet<Order> Orders { get; set; }

        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            base.OnModelCreating(modelBuilder);

            // VULNERABILITY: Hardcoded admin user with weak password
            modelBuilder.Entity<User>().HasData(
                new User
                {
                    Id = 1,
                    Username = "admin",
                    Password = "admin123", // Plaintext password
                    Email = "admin@vulnerable.com",
                    ApiKey = "sk-1234567890abcdefghijk",
                    CreatedDate = DateTime.Now,
                    IsAdmin = true,
                    CreditCardNumber = "4532-1234-5678-9010",
                    SocialSecurityNumber = "123-45-6789"
                },
                new User
                {
                    Id = 2,
                    Username = "user1",
                    Password = "password123",
                    Email = "user1@vulnerable.com",
                    CreatedDate = DateTime.Now,
                    IsAdmin = false
                }
            );

            modelBuilder.Entity<Product>().HasData(
                new Product { Id = 1, Name = "Laptop", Description = "Gaming Laptop", Price = 1200, Stock = 10, CreatedDate = DateTime.Now },
                new Product { Id = 2, Name = "Mouse", Description = "Wireless Mouse", Price = 50, Stock = 100, CreatedDate = DateTime.Now },
                new Product { Id = 3, Name = "Keyboard", Description = "Mechanical Keyboard", Price = 150, Stock = 50, CreatedDate = DateTime.Now }
            );
        }
    }
}
