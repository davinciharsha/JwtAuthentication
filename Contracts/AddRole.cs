using System.ComponentModel.DataAnnotations;

namespace JwtAuthentication.Contracts
{
    public class AddRole
    {
        [Required]
        public string Email { get; set; }
        [Required]
        public string Password { get; set; }
        [Required]
        public string Role { get; set; }
    }
}
