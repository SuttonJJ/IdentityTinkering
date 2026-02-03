using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using IdentityTinkering.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;

namespace IdentityTinkering.Controllers;

[ApiController]
[Route("api/[controller]")]
public class AuthController(IdentityContext context, IConfiguration configuration, UserManager<IdentityUser> userManager, SignInManager<IdentityUser> signInManager) : ControllerBase
{
    [HttpPost("register")]
    public async Task<IActionResult> Register(RegisterDto request)
    {
        var existingUser = await userManager.FindByEmailAsync(request.Email);
        if (existingUser != null) return BadRequest("User with this email already exists");
        
        IdentityUser user = new IdentityUser
        {
            UserName = request.Email, 
            Email = request.Email
        };
        
        IdentityResult result = await userManager.CreateAsync(user, request.Password);

        if (!result.Succeeded)
        {
            return BadRequest(new { errors = result.Errors.Select(e => e.Description) });
        }

        return Ok($"Successfully registered {user.Email}");   
    }


    [HttpPost("login")]
    public async Task<IActionResult> Login(LoginDto request)
    {
        var user = await userManager.FindByEmailAsync(request.Email);

        if (user == null || !await userManager.CheckPasswordAsync(user, request.Password)) return Unauthorized("Invalid email or password");

        var token = await GenerateJwtToken(user);
        
        return Ok(new LoginResponseDto
        {
            Token = token,
            Email = user.Email
        });
    }

    
    [HttpPost("logout")]
    public IActionResult Logout()
    {
        return Ok("Logged out");
    }
    
    
    // For testing purposes, deletes all users
    [HttpDelete("clear")]
    public async Task<IActionResult> ClearUserDb()
    {
        await context.Users.ExecuteDeleteAsync();

        return NoContent();
    }

    private async Task<string> GenerateJwtToken(IdentityUser user)
    {
        var claims = new List<Claim>
        {
            new Claim(JwtRegisteredClaimNames.Sub, user.Id),
            new Claim(JwtRegisteredClaimNames.Email, user.Email!),
            new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
            new Claim(ClaimTypes.NameIdentifier, user.Id),
            new Claim(ClaimTypes.Name, user.UserName!)
        };

        var roles = await userManager.GetRolesAsync(user);

        foreach (var role in roles)
        {
            claims.Add(new Claim(ClaimTypes.Role, role));
        }

        var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(configuration["Jwt:Secret"]));

        var credentials = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);
        
        var token = new JwtSecurityToken(
            issuer: configuration["Jwt:Issuer"],
            audience: configuration["Jwt:Audience"],
            claims: claims,
            expires: DateTime.UtcNow.AddMinutes(
                double.Parse(configuration["Jwt:ExpiresInMinutes"]!)),
            signingCredentials: credentials
        );

        return new JwtSecurityTokenHandler().WriteToken(token);
    }
}