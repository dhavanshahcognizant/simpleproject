using Microsoft.EntityFrameworkCore;
using VulnerableApp.Data;

var builder = WebApplication.CreateBuilder(args);

// VULNERABILITY: CORS policy is too permissive
builder.Services.AddCors(options =>
{
    options.AddPolicy("AllowAll", builder =>
    {
        builder.AllowAnyOrigin()      // VULNERABILITY: Allows any origin
               .AllowAnyMethod()      // VULNERABILITY: Allows any HTTP method
               .AllowAnyHeader();     // VULNERABILITY: Allows any header
    });
});

// Add services to the container
builder.Services.AddControllers();
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();
// VULNERABILITY: Session without secure configuration
builder.Services.AddDistributedMemoryCache(); // In-memory cache for sessions
builder.Services.AddSession(options =>
{
    // VULNERABILITY: Long timeout
    options.IdleTimeout = TimeSpan.FromHours(24);
    // Missing: IsEssential = true for secure configuration
});

// VULNERABILITY: Database connection with minimal security
var connectionString = builder.Configuration.GetConnectionString("DefaultConnection") 
    ?? "Data Source=vulnerable.db";
builder.Services.AddDbContext<VulnerableDbContext>(options =>
{
    options.UseSqlite(connectionString);
});

// VULNERABILITY: No authentication or authorization middleware configured
builder.Services.AddAuthentication(); // Empty - no schemes configured
builder.Services.AddAuthorization();

var app = builder.Build();

// VULNERABILITY: Error details exposed in all environments
app.UseDeveloperExceptionPage(); // Should only be in Development

// Configure the HTTP request pipeline
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

// VULNERABILITY: HTTPS not enforced
// app.UseHttpsRedirection();

app.UseRouting();
app.UseCors("AllowAll"); // Permissive CORS
app.UseSession();

// VULNERABILITY: No rate limiting
// VULNERABILITY: No request size limits
// Missing: app.UseRateLimiter();

// Root endpoint handler
app.MapGet("/", () => 
{
    return Results.Ok(new 
    { 
        message = "Vulnerable .NET 8 Application",
        documentation = "/swagger",
        version = "1.0",
        warning = "This application contains intentional security vulnerabilities for testing purposes only."
    });
});

app.MapControllers();

// Initialize database
using (var scope = app.Services.CreateScope())
{
    var dbContext = scope.ServiceProvider.GetRequiredService<VulnerableDbContext>();
    dbContext.Database.EnsureCreated();
}

app.Run();

