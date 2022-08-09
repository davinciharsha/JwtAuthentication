using JwtAuthentication.Contracts;

namespace JwtAuthentication.Interfaces
{
    public interface IUserService
    {
        Task<string> RegisterAsync(RegisterUser model);
        Task<AuthenticationInfo> GetTokenAsync(TokenRequest model);
        Task<string> AddRoleAsync(AddRole model);
        Task<AuthenticationInfo> RefreshTokenAsync(string token);
        bool RevokeToken(string token);
    }
}
