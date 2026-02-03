using System.Security.Claims;
using IdentityTinkering.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace IdentityTinkering.Controllers;


[ApiController]
[Route("api/[controller]")]
public class RolesController(IdentityContext context, RoleManager<IdentityRole> roleManager, UserManager<IdentityUser> userManager) : ControllerBase
{
    [Authorize(Roles = "admin")]
    [HttpPost("create-role")]
    public async Task<IActionResult> CreateRole([FromBody] CreateRoleRequest request)
    {
        if (string.IsNullOrWhiteSpace(request.RoleName)) return BadRequest("Role name cannot be empty");
        
        var roleExists = await roleManager.RoleExistsAsync(request.RoleName);
        if (roleExists) return BadRequest("Role already exists");

        var result = await roleManager.CreateAsync(new IdentityRole(request.RoleName));

        if (!result.Succeeded) return BadRequest(result.Errors);
            
        return Ok($"Role '{request.RoleName}' has been created successfully");
    }

    
    [HttpPost("assign-role")]
    public async Task<IActionResult> AssignRole([FromBody] AssignRoleRequest request)
    {
        // check the user exists
        var user = await userManager.FindByEmailAsync(request.Email);
        if (user == null) return NotFound("User does not exist");

        // Check the role exists
        var roleExists = await roleManager.RoleExistsAsync(request.Role);
        if (roleExists == false) return NotFound("Role does not exist");

        var userRoles = await userManager.GetRolesAsync(user);
        
        if (userRoles.Contains(request.Role))
        {
            return BadRequest("User already has this role");
        }

        // add the role to the user
        var result = await userManager.AddToRoleAsync(user, request.Role);

        if (!result.Succeeded) return BadRequest(result.Errors);
        
        return Ok($"Role '{request.Role}' assigned to {request.Email}");
    }

    [HttpPost("add-permission")]
    public async Task<IActionResult> AddPermissionToRole([FromBody] AddPermissionRequest request)
    {
        var role = await roleManager.FindByNameAsync(request.RoleName);
        if (role == null) return NotFound("Role was not found");

        var claim = new Claim("Permission", request.Permission);
        var result = await roleManager.AddClaimAsync(role, claim);
        
        if (!result.Succeeded)
            return BadRequest(result.Errors);

        return Ok($"Claim added to role '{request.RoleName}' successfully" );
    }

    [HttpGet("{roleName}/permissions")]
    public async Task<IActionResult> GetRolePermissions(string roleName)
    {
        var role = await roleManager.FindByNameAsync(roleName);
        if (role == null) return NotFound("Role cannot be found");

        var claims = await roleManager.GetClaimsAsync(role);
        var permissions = claims
            .Where(c => c.Type == "Permission")
            .Select(c => c.Value)
            .ToList();

        if (permissions.Count == 0)
        {
            return Ok("This role has no permissions");
        }

        return Ok(new { roleName, permissions });
    }
    
    
    [HttpDelete("clear")]
    public async Task<IActionResult> ClearRoles()
    {
        await context.Roles.ExecuteDeleteAsync();

        return NoContent();
    }
}