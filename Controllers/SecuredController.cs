using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace JwtAuthentication.Controllers
{
    [Authorize]
    [Route("api/[controller]")]
    [ApiController]
    public class SecuredController : ControllerBase
    {
        [HttpGet]
        public async Task<IActionResult> OnlyAuthenticationRequired()
        {
            return Ok("This is available only for Authenticated Users. Yay, you are an Authenticated user.");
        }

        [HttpPost]
        [Authorize(Roles = "Administrator")]
        public async Task<IActionResult> PostAsAdministrator()
        {
            return Ok("This is available only for Authorized Administrator Users. Yay, you are an Administrator.");
        }
    }
}
