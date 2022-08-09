using System.ComponentModel.DataAnnotations;

namespace JwtAuthentication.Contracts
{
    public class TokenRequest
    {
        [Required]
        public string Email { get; set; }
        [Required]
        public string Password { get; set; }
    }
}
