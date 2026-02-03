using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;
using IdentityTinkering.Constants;

namespace IdentityTinkering.Controllers;

[ApiController]
[Route("api/[controller]")]
public class TestController : ControllerBase
{
    [Authorize]
    [HttpGet("protected")]
    public IActionResult CheckAuthentication()
    {
        var userId = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
        var email = User.FindFirst(ClaimTypes.Email)?.Value;

        return Ok(new
        {
            message = "You are authenticated!",
            userId = userId,
            email = email
        });
    }

    [Authorize]
    [HttpGet("list-roles")]
    public IActionResult ListUserRoles()
    {
        var roles = User.FindAll(ClaimTypes.Role).Select(c => c.Value).ToList();
        return Ok(new { roles });
    }

    [Authorize(Policy = Permissions.ViewRoles)]
    public IActionResult AllUsersCanCall()
    {
        return Ok("You called this endpoint! All users can call it.");
    }

    [Authorize(Policy = Permissions.EditRoles)]
    public IActionResult OnlyAdmins()
    {
        return Ok("You must be an admin to call this endpoint!");
    }
}