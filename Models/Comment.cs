namespace VulnerableApp.Models
{
    public class Comment
    {
        public int Id { get; set; }
        public int ProductId { get; set; }
        public int UserId { get; set; }
        // VULNERABILITY: Storing unvalidated user input
        public string CommentText { get; set; }
        public DateTime CreatedDate { get; set; }
    }
}
