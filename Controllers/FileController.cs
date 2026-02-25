using Microsoft.AspNetCore.Mvc;

namespace VulnerableApp.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class FileController : ControllerBase
    {
        // VULNERABILITY: Path Traversal / Directory Traversal
        [HttpGet("read")]
        public IActionResult ReadFile(string filepath)
        {
            // CRITICAL: No path validation - vulnerable to path traversal
            // Attacker can use: ../../sensitive/file.txt or ..\\..\\windows\\system32\\
            try
            {
                var content = System.IO.File.ReadAllText(filepath);
                return Ok(new { content = content });
            }
            catch (Exception ex)
            {
                return BadRequest($"Error: {ex.Message}");
            }
        }

        // VULNERABILITY: Unrestricted File Upload
        [HttpPost("upload")]
        public IActionResult UploadFile(IFormFile file)
        {
            // VULNERABILITY: No file type validation
            // VULNERABILITY: No file size limit
            // VULNERABILITY: No file name sanitization
            try
            {
                if (file == null || file.Length == 0)
                    return BadRequest("Invalid file");

                // VULNERABILITY: No validation - could upload .exe, .aspx, or potentially harmful files
                string uploadPath = Path.Combine(Directory.GetCurrentDirectory(), "uploads");
                
                if (!Directory.Exists(uploadPath))
                    Directory.CreateDirectory(uploadPath);

                // VULNERABILITY: Using original filename without sanitization
                // Attacker could use: ../../web/shell.aspx
                string filePath = Path.Combine(uploadPath, file.FileName);

                using (var stream = new FileStream(filePath, FileMode.Create))
                {
                    file.CopyTo(stream);
                }

                return Ok(new { message = "File uploaded successfully", path = filePath });
            }
            catch (Exception ex)
            {
                return BadRequest($"Upload error: {ex.Message}");
            }
        }

        // VULNERABILITY: File Deletion without authorization
        [HttpDelete("delete")]
        public IActionResult DeleteFile(string filepath)
        {
            // No authorization check
            // No path validation
            try
            {
                System.IO.File.Delete(filepath);
                return Ok("File deleted");
            }
            catch (Exception ex)
            {
                return BadRequest($"Error: {ex.Message}");
            }
        }

        // VULNERABILITY: Information Disclosure - Directory Listing
        [HttpGet("list")]
        public IActionResult ListFiles(string directory)
        {
            // VULNERABILITY: No path validation
            try
            {
                var files = Directory.GetFiles(directory);
                var dirs = Directory.GetDirectories(directory);

                return Ok(new
                {
                    Files = files.Select(f => new FileInfo(f)).Select(f => new
                    {
                        Name = f.Name,
                        Size = f.Length,
                        Created = f.CreationTime
                    }),
                    Directories = dirs
                });
            }
            catch (Exception ex)
            {
                return BadRequest($"Error: {ex.Message}");
            }
        }

        // VULNERABILITY: Symbolic Link Following
        [HttpGet("follow-link")]
        public IActionResult FollowLink(string linkPath)
        {
            // VULNERABILITY: Following symlinks without validation
            // Could access protected files through symbolic links
            try
            {
                var content = System.IO.File.ReadAllText(linkPath);
                return Ok(new { content = content });
            }
            catch (Exception ex)
            {
                return BadRequest($"Error: {ex.Message}");
            }
        }

        // VULNERABILITY: Zip bomb / Archive bomb protection missing
        [HttpPost("extract")]
        public IActionResult ExtractArchive(string archivePath)
        {
            // VULNERABILITY: No size validation before extraction
            // Could cause DoS with zip bombs
            try
            {
                string extractPath = Path.Combine(Directory.GetCurrentDirectory(), "extracted");
                System.IO.Compression.ZipFile.ExtractToDirectory(archivePath, extractPath);
                return Ok("Archive extracted");
            }
            catch (Exception ex)
            {
                return BadRequest($"Error: {ex.Message}");
            }
        }
    }
}
