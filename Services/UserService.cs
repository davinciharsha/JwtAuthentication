using JwtAuthentication.Constants;
using JwtAuthentication.Contracts;
using JwtAuthentication.Interfaces;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace JwtAuthentication.Services
{
public class UserService : IUserService
{
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly Jwt _jwt;

        public UserService(UserManager<ApplicationUser> userManager, IOptions<Jwt> jwt)
        {
            _userManager = userManager;
            _jwt = jwt.Value;
        }

        public async Task<string> RegisterAsync(RegisterUser userInfo)
        {
            var user = new ApplicationUser
            {
                UserName = userInfo.Username,
                Email = userInfo.Email,
                FirstName = userInfo.FirstName,
                LastName = userInfo.LastName
            };

            var userWithSameEmail = await _userManager.FindByEmailAsync(userInfo.Email);
            if (userWithSameEmail == null)
            {
                var result = await _userManager.CreateAsync(user, userInfo.Password);
                if (result.Succeeded)
                {
                    await _userManager.AddToRoleAsync(user, Authorization.default_role.ToString());

                }
                return $"User Registered with username {user.UserName}";
            }
            else
            {
                return $"Email {user.Email} is already registered.";
            }
        }

        public async Task<AuthenticationInfo> GetTokenAsync(TokenRequest tokenRequest)
        {
            var authenticationInfo = new AuthenticationInfo();
            var user = await _userManager.FindByEmailAsync(tokenRequest.Email);
            
            if (user == null)
            {
                authenticationInfo.IsAuthenticated = false;
                authenticationInfo.Message = $"No Account found with {tokenRequest.Email}.";
                return authenticationInfo;
            }
            
            if (await _userManager.CheckPasswordAsync(user, tokenRequest.Password))
            {
                authenticationInfo.IsAuthenticated = true;
                JwtSecurityToken jwtSecurityToken = await CreateJwtToken(user);
                authenticationInfo.Token = new JwtSecurityTokenHandler().WriteToken(jwtSecurityToken);
                authenticationInfo.Email = user.Email;
                authenticationInfo.UserName = user.UserName;
                var rolesList = await _userManager.GetRolesAsync(user).ConfigureAwait(false);
                authenticationInfo.Roles = rolesList.ToList();
                return authenticationInfo;
            }

            authenticationInfo.IsAuthenticated = false;
            authenticationInfo.Message = $"Incorrect credentials provided for user {user.Email}.";
            return authenticationInfo;
        }

        private async Task<JwtSecurityToken> CreateJwtToken(ApplicationUser user)
        {
            var userClaims = await _userManager.GetClaimsAsync(user);
            var roles = await _userManager.GetRolesAsync(user);

            var roleClaims = new List<Claim>();

            foreach (var role in roles)
            {
                roleClaims.Add(new Claim("roles", role));
            }

            var claims = new[]
            {
                new Claim(JwtRegisteredClaimNames.Name, user.UserName),
                new Claim(JwtRegisteredClaimNames.NameId, Guid.NewGuid().ToString()),
                new Claim(JwtRegisteredClaimNames.Email, user.Email),
                new Claim("uid", user.Id)
            }
            .Union(userClaims)
            .Union(roleClaims);

            var symmetricSecurityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_jwt.Key));
            var signingCredentials = new SigningCredentials(symmetricSecurityKey, SecurityAlgorithms.HmacSha256);

            var jwtSecurityToken = new JwtSecurityToken(
                issuer: _jwt.Issuer,
                audience: _jwt.Audience,
                claims: claims,
                expires: DateTime.UtcNow.AddMinutes(_jwt.DurationInMinutes),
                signingCredentials: signingCredentials);
            return jwtSecurityToken;
        }

        public async Task<string> AddRoleAsync(AddRole addRole)
        {
            var user = await _userManager.FindByEmailAsync(addRole.Email);
            
            if (user == null)
            {
                return $"No account registered with {addRole.Email}.";
            }

            if (await _userManager.CheckPasswordAsync(user, addRole.Password))
            {
                var roleExists = Enum.GetNames(typeof(Authorization.Roles)).Any(x => x.ToLower() == addRole.Role.ToLower());
                if (roleExists)
                {
                    await _userManager.AddToRoleAsync(user, addRole.Role);
                    return $"Added {addRole.Role} to user {addRole.Email}.";
                }
                return $"Role {addRole.Role} not found.";
            }
            return $"Incorrect credentials provided for user {user.Email}.";
        }
    }
}
