using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using IdentityTinkering.Models;
using IdentityTinkering.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;

namespace IdentityTinkering.Controllers;

[ApiController]
[Route("api/[controller]")]
public class AuthController(IdentityContext context, IConfiguration configuration, UserManager<ApplicationUser> userManager, 
    SignInManager<ApplicationUser> signInManager, TokenService tokenService) : ControllerBase
{
    [HttpPost("register")]
    public async Task<IActionResult> Register(RegisterDto request)
    {
        var existingUser = await userManager.FindByEmailAsync(request.Email);
        if (existingUser != null) return BadRequest("User with this email already exists");
        
        ApplicationUser user = new ApplicationUser
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

        var accessToken = await tokenService.GenerateJwtToken(user);
        var refreshToken = tokenService.GenerateRefreshToken();

        user.RefreshToken = refreshToken;
        user.RefreshTokenExpiryTime = DateTime.UtcNow.AddDays(7);
        await userManager.UpdateAsync(user);
        
        return Ok(new LoginResponseDto
        {
            AccessToken = accessToken,
            RefreshToken = refreshToken,
            Email = user.Email
        });
    }
    
    [Authorize]
    [HttpPost("logout")]
    public async Task<IActionResult> Logout()
    {
        var username = User.Identity?.Name;
        if (username == null) return Ok("Logged out");

        var user = await userManager.FindByNameAsync(username);
        if (user != null)
        {
            user.RefreshToken = null;
            await userManager.UpdateAsync(user);
        }

        return Ok("Logged out");
    }
    
    
    // For development testing purposes, deletes all users
    [HttpDelete("clear")]
    public async Task<IActionResult> ClearUserDb()
    {
        await context.Users.ExecuteDeleteAsync();

        return NoContent();
    }
    
    
    
    // Token management
    [HttpPost("refresh")]
    public async Task<IActionResult> RefreshToken([FromBody] TokenRequest request)
    {
        if (request == null) return BadRequest("Invalid request");

        string accessToken = request.AccessToken;
        string refreshToken = request.RefreshToken;
        
        ClaimsPrincipal principal;
        try
        {
            principal = tokenService.GetPrincipalFromExpiredToken(accessToken);
        }
        catch
        {
            return BadRequest("Invalid access token");
        }

        string? username = principal.Identity?.Name;
        if (string.IsNullOrEmpty(username))
        {
            return BadRequest("Invalid token claims");
        }
        var user = await userManager.FindByNameAsync(username);
        
        if (user == null || 
            user.RefreshToken != refreshToken || 
            user.RefreshTokenExpiryTime <= DateTime.UtcNow)
        {
            return BadRequest("Invalid refresh token");
        }

        var newAccessToken = await tokenService.GenerateJwtToken(user);
        var newRefreshToken = tokenService.GenerateRefreshToken();
        
        user.RefreshToken = newRefreshToken;
        await userManager.UpdateAsync(user);

        return Ok(new
        {
            AccessToken = newAccessToken,
            RefreshToken = newRefreshToken
        });
    }
}