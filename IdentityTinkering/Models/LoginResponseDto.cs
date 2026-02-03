namespace IdentityTinkering.Models;

public class LoginResponseDto
{
    public string AccessToken { get; set; } = string.Empty;
    public string RefreshToken { get; set; } = string.Empty;
    public string Email { get; set; } = string.Empty;
    public DateTime Expiry { get; set; } = DateTime.UtcNow.AddMinutes(15);
}