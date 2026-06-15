using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Diagnostics;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using Portofolio.Data;
using Portofolio.LoggingServices;
using Portofolio.MiddleWares;
using Portofolio.Services.AuthServices;
using Portofolio.Services.ExperienceServices;
using Portofolio.Services.ImageServices;
using Portofolio.Services.JWTServices;
using Portofolio.Services.ProfileServices;
using System.Text;
using System.Threading.RateLimiting;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddControllers();

// Database
builder.Services.AddDbContext<ApplicationDbContext>(options =>
    options.UseSqlServer(builder.Configuration.GetConnectionString("DefaultConnection")));

// Needed to access HttpContext inside services (used in AuthServices to read the token header)
builder.Services.AddHttpContextAccessor();

// My services
builder.Services.AddScoped<IImageServices, ImageServices>();
builder.Services.AddScoped<IProfileServices, ProfileServices>();
builder.Services.AddScoped<IExperienceServices, ExperienceServices>();
builder.Services.AddScoped<IAuthServices, AuthServices>();
builder.Services.AddScoped<IJwtServices, JwtServices>();
builder.Services.AddSingleton<ISimpleLogger, SimpleLogger>();

// rate limiting
builder.Services.AddRateLimiter(options =>
{
    options.GlobalLimiter = PartitionedRateLimiter.Create<HttpContext, string>(httpContext =>
        RateLimitPartition.GetSlidingWindowLimiter(
            partitionKey: httpContext.User.Identity?.Name ?? httpContext.Request.Headers.Host.ToString(),
            factory: partition => new SlidingWindowRateLimiterOptions
            {
                AutoReplenishment = true,
                PermitLimit = 40,
                QueueLimit = 0,
                Window = TimeSpan.FromMinutes(1)
            }));
});

// cache services 
builder.Services.AddHybridCache();

builder.Services.AddControllers()
    .AddJsonOptions(options =>
    {
        // This ignores cycles and prevents the error
        options.JsonSerializerOptions.ReferenceHandler = System.Text.Json.Serialization.ReferenceHandler.IgnoreCycles;

        // Optional: Make JSON pretty
        options.JsonSerializerOptions.WriteIndented = true;
    });

// JWT setup
builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidateAudience = true,
            ValidateLifetime = true,
            ValidateIssuerSigningKey = true,
            ValidIssuer = builder.Configuration["Jwt:Issuer"],
            ValidAudience = builder.Configuration["Jwt:Audience"],
            IssuerSigningKey = new SymmetricSecurityKey(
                Encoding.UTF8.GetBytes(builder.Configuration["Jwt:Key"]!))
        };

        // After the token passes normal validation, we also check if the user logged out
        // by looking up the token in our blacklist table
        options.Events = new JwtBearerEvents
        {
            OnTokenValidated = async context =>
            {
                var db = context.HttpContext.RequestServices
                    .GetRequiredService<ApplicationDbContext>();

                var token = context.HttpContext.Request.Headers["Authorization"]
                    .ToString().Replace("Bearer ", "");

                bool isBlacklisted = await db.BlacklistedTokens
                    .AnyAsync(t => t.Token == token);

                if (isBlacklisted)
                    context.Fail("Token has been revoked.");
            }
        };
    });

builder.Services.AddAuthorization();

var app = builder.Build();

// Logger middeleware 
app.UseMiddleware<RequestLoggerMiddleware>();

// Catches any unhandled exception across the whole app and returns a clean JSON error
// instead of crashing or leaking internal details
app.UseExceptionHandler(appError =>
{
    appError.Run(async context =>
    {
        var contextFeature = context.Features.Get<IExceptionHandlerFeature>();
        var ex = contextFeature?.Error;

        context.Response.ContentType = "application/json";

        context.Response.StatusCode = ex switch
        {
            KeyNotFoundException => StatusCodes.Status404NotFound,
            UnauthorizedAccessException => StatusCodes.Status401Unauthorized,
            InvalidOperationException => StatusCodes.Status400BadRequest,
            _ => StatusCodes.Status500InternalServerError
        };

        await context.Response.WriteAsJsonAsync(new
        {
            statusCode = context.Response.StatusCode,
            message = ex?.Message ?? "An unexpected error occurred."
        });
    });
});

if (!app.Environment.IsDevelopment())
{
    app.UseHsts();
}

app.UseHttpsRedirection();
app.UseRouting();

// Order matters here — authentication has to run before authorization
app.UseAuthentication();
app.UseAuthorization();

app.MapControllers();

app.Run();