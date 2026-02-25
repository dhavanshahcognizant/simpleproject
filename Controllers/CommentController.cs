using Microsoft.AspNetCore.Mvc;
using VulnerableApp.Data;
using VulnerableApp.Models;
using System.Text.Encodings.Web;

namespace VulnerableApp.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class CommentController : ControllerBase
    {
        private readonly VulnerableDbContext _dbContext;

        public CommentController(VulnerableDbContext dbContext)
        {
            _dbContext = dbContext;
        }

        // VULNERABILITY: Cross-Site Scripting (XSS) - Stored
        [HttpPost("add")]
        public IActionResult AddComment([FromBody] CommentRequest request)
        {
            // VULNERABILITY: No input sanitization or encoding
            var comment = new Comment
            {
                ProductId = request.ProductId,
                UserId = request.UserId,
                CommentText = request.CommentText, // Directly storing unsanitized input
                CreatedDate = DateTime.Now
            };

            _dbContext.Comments.Add(comment);
            _dbContext.SaveChanges();

            return Ok("Comment added");
        }

        // VULNERABILITY: Reflected XSS
        [HttpGet("search")]
        public IActionResult SearchComments(string keyword)
        {
            // VULNERABILITY: Returning unencoded user input in response
            var comments = _dbContext.Comments
                .Where(c => c.CommentText.Contains(keyword))
                .ToList();

            // VULNERABILITY: Directly returning HTML with user input
            string html = $@"
<html>
<body>
<h1>Search Results for: {keyword}</h1>
<ul>";
            
            foreach (var comment in comments)
            {
                // XSS vulnerability - keyword is returned as-is
                html += $"<li><strong>Comment ID {comment.Id}:</strong> {comment.CommentText}</li>";
            }
            
            html += "</ul></body></html>";

            return Content(html, "text/html");
        }

        // VULNERABILITY: Insecure Direct Object Reference (IDOR)
        [HttpGet("{id}")]
        public IActionResult GetComment(int id)
        {
            // No authorization check - anyone can read any comment
            var comment = _dbContext.Comments.FirstOrDefault(c => c.Id == id);
            
            if (comment == null)
                return NotFound();

            return Ok(comment);
        }

        // VULNERABILITY: Missing authentication and authorization
        [HttpDelete("{id}")]
        public IActionResult DeleteComment(int id)
        {
            // No authentication, anyone can delete any comment
            var comment = _dbContext.Comments.FirstOrDefault(c => c.Id == id);
            
            if (comment == null)
                return NotFound();

            _dbContext.Comments.Remove(comment);
            _dbContext.SaveChanges();

            return Ok("Comment deleted");
        }

        // VULNERABILITY: Batch processing without input validation
        [HttpPost("batch-delete")]
        public IActionResult BatchDeleteComments([FromBody] int[] commentIds)
        {
            // VULNERABILITY: No validation on array size - potential DoS
            // VULNERABILITY: No authorization
            foreach (int id in commentIds)
            {
                var comment = _dbContext.Comments.FirstOrDefault(c => c.Id == id);
                if (comment != null)
                {
                    _dbContext.Comments.Remove(comment);
                }
            }
            _dbContext.SaveChanges();
            return Ok($"Deleted {commentIds.Length} comments");
        }

        // VULNERABILITY: SQL Injection in sort parameter
        [HttpGet("list")]
        public IActionResult ListComments(string sortBy)
        {
            // VULNERABILITY: Direct string concatenation in LINQ (if using raw SQL)
            // In this case, shown conceptually - actual SQL injection
            var comments = _dbContext.Comments.AsEnumerable();

            // VULNERABILITY: Unsafe string eval if converted to raw SQL
            comments = sortBy switch
            {
                "id asc" => comments.OrderBy(c => c.Id),
                "id desc" => comments.OrderByDescending(c => c.Id),
                "1=1 OR 1=1" => comments, // SQL injection attempt
                _ => comments.OrderByDescending(c => c.CreatedDate)
            };

            return Ok(comments.ToList());
        }
    }

    public class CommentRequest
    {
        public int ProductId { get; set; }
        public int UserId { get; set; }
        public string CommentText { get; set; }
    }
}
