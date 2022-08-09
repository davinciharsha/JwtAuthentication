using Microsoft.AspNetCore.Identity;

namespace JwtAuthentication.Contracts
{
    public class ApplicationUser : IdentityUser
    {
        public string FirstName { get; set; }
        public string LastName { get; set; }
    }
}
