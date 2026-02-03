using System.Security.Claims;
using IdentityTinkering.Constants;
using Microsoft.AspNetCore.Identity;

namespace IdentityTinkering.Services;

public static class RoleSeeder
{
    public static async Task SeedRolesAndPermissions(RoleManager<IdentityRole> roleManager, UserManager<IdentityUser> userManager)
    {
        await SeedAdminRole(roleManager);
        await SeedUserRole(roleManager);
        await SeedAdmins(userManager);
    }

    private static async Task SeedAdminRole(RoleManager<IdentityRole> roleManager)
    {
        if (await roleManager.RoleExistsAsync("Admin"))
            return;

        var adminRole = new IdentityRole("Admin");
        await roleManager.CreateAsync(adminRole);

        // Role Permissions
        await roleManager.AddClaimAsync(adminRole, new Claim("Permission", Permissions.ViewRoles));
        await roleManager.AddClaimAsync(adminRole, new Claim("Permission", Permissions.EditRoles));
    }

    private static async Task SeedUserRole(RoleManager<IdentityRole> roleManager)
    {
        if (await roleManager.RoleExistsAsync("User"))
            return; 

        var userRole = new IdentityRole("User");
        await roleManager.CreateAsync(userRole);

        await roleManager.AddClaimAsync(userRole, new Claim("Permission", Permissions.ViewRoles));
    }

    private static async Task SeedAdmins(UserManager<IdentityUser> userManager)
    {
        var user = await userManager.FindByEmailAsync("Johannes.sutton2003@gmail.com");
        if (user == null || await userManager.IsInRoleAsync(user, "Admin")) return;

        await userManager.AddToRolesAsync(user, new List<string>{"admin", "user"});
    }
}