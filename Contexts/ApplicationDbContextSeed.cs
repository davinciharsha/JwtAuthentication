using JwtAuthentication.Constants;
using JwtAuthentication.Contracts;
using Microsoft.AspNetCore.Identity;

namespace JwtAuthentication.Contexts
{
    public class ApplicationDbContextSeed
    {
        public static async Task SeedDataAsync(UserManager<ApplicationUser> userManager, RoleManager<IdentityRole> roleManager)
        {
            //Seed Roles first
            await roleManager.CreateAsync(new IdentityRole(Authorization.Roles.Administrator.ToString()));
            await roleManager.CreateAsync(new IdentityRole(Authorization.Roles.Moderator.ToString()));
            await roleManager.CreateAsync(new IdentityRole(Authorization.Roles.User.ToString()));

            //Seed Default User
            var defaultUser = new ApplicationUser
            { 
                FirstName = "Sai SriHarsha", 
                LastName = "Y", 
                UserName = Authorization.default_username, 
                Email = Authorization.default_email, 
                EmailConfirmed = true, 
                PhoneNumberConfirmed = true 
            };

            await userManager.CreateAsync(defaultUser, Authorization.default_password);
            await userManager.AddToRoleAsync(defaultUser, Authorization.default_role.ToString());
        }
    }
}
