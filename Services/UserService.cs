using JwtAuthentication.Constants;
using JwtAuthentication.Contracts;
using JwtAuthentication.Interfaces;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using System.Security.Cryptography;
using JwtAuthentication.Contexts;

namespace JwtAuthentication.Services
{
public class UserService : IUserService
{
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly Jwt _jwt;
        private readonly ApplicationDbContext _context;

        public UserService(UserManager<ApplicationUser> userManager, IOptions<Jwt> jwt, ApplicationDbContext context)
        {
            _userManager = userManager;
            _jwt = jwt.Value;
            _context = context;
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

                if (user.RefreshTokens.Any(a => a.IsActive))
                {
                    var activeRefreshToken = user.RefreshTokens.Where(a => a.IsActive == true).FirstOrDefault();
                    authenticationInfo.RefreshToken = activeRefreshToken.Token;
                    authenticationInfo.RefreshTokenExpiration = activeRefreshToken.Expires;
                }
                else
                {
                    var refreshToken = CreateRefreshToken();
                    authenticationInfo.RefreshToken = refreshToken.Token;
                    authenticationInfo.RefreshTokenExpiration = refreshToken.Expires;
                    user.RefreshTokens.Add(refreshToken);
                    _context.Update(user);
                    _context.SaveChanges();
                }

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

        private RefreshToken CreateRefreshToken()
        {
            var randomNumber = new byte[32];
            using (var generator = new RNGCryptoServiceProvider())
            {
                generator.GetBytes(randomNumber);
                return new RefreshToken
                {
                    Token = Convert.ToBase64String(randomNumber),
                    Expires = DateTime.UtcNow.AddDays(10),
                    Created = DateTime.UtcNow
                };

            }
        }

        public async Task<AuthenticationInfo> RefreshTokenAsync(string rtoken)
        {
            var authenticationModel = new AuthenticationInfo();
            var user = _context.Users.SingleOrDefault(u => u.RefreshTokens.Any(t => t.Token == rtoken));
            if (user == null)
            {
                authenticationModel.IsAuthenticated = false;
                authenticationModel.Message = $"Refresh token did not match any users.";
                return authenticationModel;
            }

            var refreshToken = user.RefreshTokens.Single(x => x.Token == rtoken);

            if (!refreshToken.IsActive)
            {
                authenticationModel.IsAuthenticated = false;
                authenticationModel.Message = $"Refresh token not active.";
                return authenticationModel;
            }

            //Revoke Current Refresh Token
            refreshToken.Revoked = DateTime.UtcNow;

            //Generate new Refresh Token and save to Database
            var newRefreshToken = CreateRefreshToken();
            user.RefreshTokens.Add(newRefreshToken);
            _context.Update(user);
            _context.SaveChanges();

            //Generates new jwt
            authenticationModel.IsAuthenticated = true;
            var rolesList = await _userManager.GetRolesAsync(user).ConfigureAwait(false);

            JwtSecurityToken jwtSecurityToken = await CreateJwtToken(user);
            authenticationModel.Token = new JwtSecurityTokenHandler().WriteToken(jwtSecurityToken);
            authenticationModel.Email = user.Email;
            authenticationModel.UserName = user.UserName;
            authenticationModel.Roles = rolesList.ToList();
            authenticationModel.RefreshToken = newRefreshToken.Token;
            authenticationModel.RefreshTokenExpiration = newRefreshToken.Expires;
            return authenticationModel;
        }

        public bool RevokeToken(string token)
        {
            var user = _context.Users.SingleOrDefault(u => u.RefreshTokens.Any(t => t.Token == token));

            if (user == null) 
                return false;

            var refreshToken = user.RefreshTokens.Single(x => x.Token == token);

            if (!refreshToken.IsActive) 
                return false;

            // if found and active, revoke token and save
            refreshToken.Revoked = DateTime.UtcNow;
            _context.Update(user);
            _context.SaveChanges();

            return true;
        }
    }
}
