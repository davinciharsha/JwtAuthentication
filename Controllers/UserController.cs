using JwtAuthentication.Contracts;
using JwtAuthentication.Interfaces;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace JwtAuthentication.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class UserController : ControllerBase
    {
        private readonly IUserService _userService;
        public UserController(IUserService userService)
        {
            _userService = userService;
        }

        [HttpPost("Registeruser")]
        public async Task<ActionResult> RegisterAsync(RegisterUser registerUser)
        {
            var result = await _userService.RegisterAsync(registerUser);
            return Ok(result);
        }

        [HttpPost("GetToken")]
        public async Task<IActionResult> GetTokenAsync(TokenRequest tokenRequest)
        {
            var result = await _userService.GetTokenAsync(tokenRequest);
            return Ok(result);
        }

        [HttpPost("AddRole")]
        public async Task<IActionResult> AddRoleAsync(AddRole addRole)
        {
            var result = await _userService.AddRoleAsync(addRole);
            return Ok(result);
        }
    }
}
