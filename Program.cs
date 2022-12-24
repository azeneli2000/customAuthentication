using System.Security.Claims;
using Microsoft.AspNetCore.DataProtection;

var builder = WebApplication.CreateBuilder(args);
builder.Services.AddDataProtection();
builder.Services.AddHttpContextAccessor();
builder.Services.AddScoped<AuthService>();

var app = builder.Build();
//auth middleware => app.AddAuthentication()
app.Use(async (ctx, next) =>
{
    var dataProtector = ctx.RequestServices.GetRequiredService<IDataProtectionProvider>();
    var s =  dataProtector.CreateProtector("auth");
    var cookie =  ctx.Request.Headers.Cookie.FirstOrDefault(x=>x.StartsWith("auth"));
    var unprotected = s.Unprotect(cookie.Split("=").Last());
    var key = unprotected.Split(":")[0];
    var value = unprotected.Split(":")[1];

    var claims = new List<Claim>();
    claims.Add(new Claim(key,value));
    var identity = new ClaimsIdentity(claims);
    var claimsPrincipal = new ClaimsPrincipal(identity);
    ctx.User = claimsPrincipal;
        await next();
});
app.MapGet("/login", (AuthService auth) =>
{
    auth.SignIn();
    return "Ok";
});
app.MapGet("/user", (HttpContext ctx) => ctx.User.FindFirst("usr").Value);

    
app.Run();

//auth service => cookie authentication handler

public class AuthService
{
    private readonly IHttpContextAccessor _accessor;
    private readonly IDataProtectionProvider _dataProtector;

    public  AuthService(IHttpContextAccessor accessor,IDataProtectionProvider dataProtector)
    {
        _accessor = accessor;
        _dataProtector = dataProtector;
    }
    public void SignIn()
    {
        var protectedCookie = _dataProtector.CreateProtector("auth").Protect("usr:Andi");
        _accessor.HttpContext.Response.Headers["set-cookie"] = "auth="+ protectedCookie;
    }

}