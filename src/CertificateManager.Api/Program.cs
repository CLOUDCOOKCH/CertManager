using System.IO.Compression;
using System.Security.Claims;
using System.Text;
using System.Text.Json.Serialization;
using CertificateManager.Application;
using CertificateManager.Domain;
using CertificateManager.Infrastructure;
using Microsoft.AspNetCore.Antiforgery;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
var builder=WebApplication.CreateBuilder(args);
if(builder.Environment.IsProduction())
{
    var databaseConnection=builder.Configuration.GetConnectionString("Database");
    var allowedHosts=builder.Configuration["AllowedHosts"];
    var seedPassword=Environment.GetEnvironmentVariable("SEED_ADMIN_PASSWORD");
    if(string.IsNullOrWhiteSpace(databaseConnection)||databaseConnection.Contains("development-only",StringComparison.OrdinalIgnoreCase))
        throw new InvalidOperationException("A production database connection must be configured.");
    if(string.IsNullOrWhiteSpace(allowedHosts)||allowedHosts=="*")
        throw new InvalidOperationException("AllowedHosts must explicitly list the production host names.");
    if(string.IsNullOrWhiteSpace(seedPassword)||seedPassword=="ChangeMe!123456")
        throw new InvalidOperationException("A non-default SEED_ADMIN_PASSWORD is required in production.");
}
builder.Services.ConfigureHttpJsonOptions(options =>
    options.SerializerOptions.Converters.Add(new JsonStringEnumConverter()));
builder.Services.AddDbContext<AppDbContext>(o=>o.UseNpgsql(builder.Configuration.GetConnectionString("Database")));
var trustForwardedHeaders = builder.Configuration.GetValue<bool>("ForwardedHeaders:TrustAll") ||
                            builder.Configuration.GetValue<bool>("ASPNETCORE_FORWARDEDHEADERS_ENABLED");
builder.Services.Configure<ForwardedHeadersOptions>(options =>
{
    options.ForwardedHeaders = ForwardedHeaders.XForwardedFor |
                               ForwardedHeaders.XForwardedProto;
    if (trustForwardedHeaders)
    {
        options.KnownNetworks.Clear();
        options.KnownProxies.Clear();
    }
});
var dataProtectionPath=builder.Configuration["DataProtection:KeysPath"]??Path.Combine(builder.Environment.ContentRootPath,"keys");
Directory.CreateDirectory(dataProtectionPath);
builder.Services.AddDataProtection().PersistKeysToFileSystem(new DirectoryInfo(dataProtectionPath));
var microsoftSection=builder.Configuration.GetSection("Authentication:Microsoft");
var microsoftTenantId=microsoftSection["TenantId"];
var microsoftClientId=microsoftSection["ClientId"];
var microsoftClientSecret=microsoftSection["ClientSecret"];
var microsoftCallbackPath=microsoftSection["CallbackPath"]??"/signin-microsoft";
var microsoftAuthEnabled=microsoftSection.GetValue<bool>("Enabled")&&!string.IsNullOrWhiteSpace(microsoftTenantId)&&!string.IsNullOrWhiteSpace(microsoftClientId)&&!string.IsNullOrWhiteSpace(microsoftClientSecret);
builder.Services
    .AddIdentity<ApplicationUser, IdentityRole>(options =>
    {
        options.User.RequireUniqueEmail = true;
        options.Password.RequiredLength = 12;
        options.Password.RequireNonAlphanumeric = true;
        options.Lockout.MaxFailedAccessAttempts = 5;
        options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(5);
        options.SignIn.RequireConfirmedAccount = false;
    })
    .AddEntityFrameworkStores<AppDbContext>()
    .AddDefaultTokenProviders();
if(microsoftAuthEnabled)
{
    builder.Services.AddAuthentication().AddOpenIdConnect("Microsoft",options=>
    {
        options.SignInScheme=IdentityConstants.ExternalScheme;
        options.Authority=$"https://login.microsoftonline.com/{microsoftTenantId}/v2.0";
        options.ClientId=microsoftClientId!;
        options.ClientSecret=microsoftClientSecret!;
        options.CallbackPath=microsoftCallbackPath;
        options.ResponseType="code";
        options.SaveTokens=false;
        options.GetClaimsFromUserInfoEndpoint=true;
        options.Scope.Clear();
        options.Scope.Add("openid");
        options.Scope.Add("profile");
        options.Scope.Add("email");
        options.Events.OnTicketReceived=async context=>
        {
            var principal=context.Principal;
            var email=principal?.FindFirstValue(ClaimTypes.Email)??principal?.FindFirst("preferred_username")?.Value;
            if(string.IsNullOrWhiteSpace(email)||!System.Net.Mail.MailAddress.TryCreate(email.Trim(),out _))
            {
                context.HandleResponse();
                context.Response.Redirect("/?microsoftError=missing-email");
                return;
            }

            email=email.Trim().ToLowerInvariant();
            var userManager=context.HttpContext.RequestServices.GetRequiredService<UserManager<ApplicationUser>>();
            var signInManager=context.HttpContext.RequestServices.GetRequiredService<SignInManager<ApplicationUser>>();
            var db=context.HttpContext.RequestServices.GetRequiredService<AppDbContext>();
            var user=await userManager.FindByEmailAsync(email);
            if(user is null)
            {
                user=new ApplicationUser
                {
                    UserName=email,
                    Email=email,
                    DisplayName=principal?.FindFirstValue("name")??email,
                    EmailConfirmed=true
                };
                var created=await userManager.CreateAsync(user,PasswordGenerator.Generate());
                if(!created.Succeeded)
                {
                    context.HandleResponse();
                    context.Response.Redirect("/?microsoftError=account-creation-failed");
                    return;
                }
            }

            if(user.LockoutEnd is not null&&user.LockoutEnd> DateTimeOffset.UtcNow)
            {
                context.HandleResponse();
                context.Response.Redirect("/?microsoftError=account-locked");
                return;
            }

            var roles=await userManager.GetRolesAsync(user);
            if(roles.Count==0)
            {
                await userManager.AddToRoleAsync(user,Roles.Reader);
            }

            await signInManager.SignInAsync(user,isPersistent:true);
            db.AuditLogs.Add(new AuditLog
            {
                Action="MICROSOFT_LOGIN",
                EntityType="User",
                EntityId=user.Id,
                IpAddress=context.HttpContext.Connection.RemoteIpAddress?.ToString(),
                UserId=user.Id,
                Result="Success"
            });
            await db.SaveChangesAsync();
            context.HandleResponse();
            context.Response.Redirect("/");
        };
        options.Events.OnRemoteFailure=context=>
        {
            context.HandleResponse();
            context.Response.Redirect("/?microsoftError=provider-failed");
            return Task.CompletedTask;
        };
    });
}
builder.Services.ConfigureApplicationCookie(options =>
{
    options.Cookie.HttpOnly = true;
    options.Cookie.SameSite = SameSiteMode.Strict;
    options.Cookie.SecurePolicy = builder.Environment.IsProduction()?CookieSecurePolicy.Always:CookieSecurePolicy.SameAsRequest;
    options.SlidingExpiration = true;
    options.ExpireTimeSpan = TimeSpan.FromHours(8);
    options.Events.OnRedirectToLogin = context =>
    {
        if (context.Request.Path.StartsWithSegments("/api"))
        {
            context.Response.StatusCode = StatusCodes.Status401Unauthorized;
            return Task.CompletedTask;
        }
        context.Response.Redirect(context.RedirectUri);
        return Task.CompletedTask;
    };
    options.Events.OnRedirectToAccessDenied = context =>
    {
        if (context.Request.Path.StartsWithSegments("/api"))
        {
            context.Response.StatusCode = StatusCodes.Status403Forbidden;
            return Task.CompletedTask;
        }
        context.Response.Redirect(context.RedirectUri);
        return Task.CompletedTask;
    };
});
builder.Services.AddAuthorization(options =>
{
    options.AddPolicy(
        "Read",
        policy => policy.RequireRole(Roles.Reader, Roles.Operator, Roles.Administrator));
    options.AddPolicy(
        "Operate",
        policy => policy.RequireRole(Roles.Operator, Roles.Administrator));
    options.AddPolicy("Admin", policy => policy.RequireRole(Roles.Administrator));
});
builder.Services.AddAntiforgery(options =>
{
    options.HeaderName = "X-XSRF-TOKEN";
    options.Cookie.Name = "XSRF-TOKEN";
    options.Cookie.Path = "/";
    options.Cookie.HttpOnly = true;
    options.Cookie.SameSite = SameSiteMode.Strict;
    options.Cookie.SecurePolicy = builder.Environment.IsProduction()?CookieSecurePolicy.Always:CookieSecurePolicy.SameAsRequest;
});
builder.Services.AddRateLimiter(options =>
    options.AddFixedWindowLimiter("api", limiter =>
    {
        limiter.PermitLimit = 100;
        limiter.Window = TimeSpan.FromMinutes(1);
        limiter.QueueLimit = 0;
    })
    .AddFixedWindowLimiter("auth", limiter =>
    {
        limiter.PermitLimit = 10;
        limiter.Window = TimeSpan.FromMinutes(5);
        limiter.QueueLimit = 0;
    }));
builder.Services.Configure<SmtpOptions>(
    builder.Configuration.GetSection(SmtpOptions.Section));
builder.Services.Configure<NotificationOptions>(
    builder.Configuration.GetSection(NotificationOptions.Section));
builder.Services.AddScoped<INotificationService, SmtpNotificationService>();
builder.Services.AddHostedService<RenewalNotificationWorker>();
builder.Services.AddSingleton<ICertificateGenerator, CertificateGenerator>();
builder.Services.AddProblemDetails();
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();
var app = builder.Build();
app.UseForwardedHeaders();
if(app.Environment.IsProduction())app.UseHsts();
app.UseExceptionHandler();
app.Use(async (context, next) =>
{
    context.Response.Headers["X-Content-Type-Options"] = "nosniff";
    context.Response.Headers["X-Frame-Options"] = "DENY";
    context.Response.Headers["Referrer-Policy"] = "no-referrer";
    context.Response.Headers["Content-Security-Policy"] =
        "default-src 'self'; style-src 'self' 'unsafe-inline'";
    await next();
});
app.UseRateLimiter();
app.UseAuthentication();
app.Use(async (context, next) =>
{
    var isApiMutation = context.Request.Path.StartsWithSegments("/api") &&
                        !HttpMethods.IsGet(context.Request.Method) &&
                        !HttpMethods.IsHead(context.Request.Method) &&
                        !HttpMethods.IsOptions(context.Request.Method);
    var isLogin = context.Request.Path.Equals(
        "/api/auth/login",
        StringComparison.OrdinalIgnoreCase);
    if (isApiMutation && !isLogin)
    {
        try
        {
            await context.RequestServices
                .GetRequiredService<IAntiforgery>()
                .ValidateRequestAsync(context);
        }
        catch (AntiforgeryValidationException)
        {
            context.Response.StatusCode = StatusCodes.Status400BadRequest;
            await context.Response.WriteAsJsonAsync(
                new { error = "Invalid antiforgery token" });
            return;
        }
    }
    await next();
});
app.UseAuthorization();
if(app.Environment.IsDevelopment()){app.UseSwagger();
app.UseSwaggerUI();
} app.UseDefaultFiles();
app.UseStaticFiles();
var api=app.MapGroup("/api").RequireRateLimiting("api");
api.MapGet("/antiforgery",(Microsoft.AspNetCore.Antiforgery.IAntiforgery a,HttpContext c)=>{c.Response.Headers.CacheControl="no-store";
var t=a.GetAndStoreTokens(c);
return Results.Ok(new{token=t.RequestToken});
});
api.MapGet("/auth/providers",()=>Results.Ok(new{microsoft=new{enabled=microsoftAuthEnabled,displayName="Microsoft"}}));
api.MapGet("/auth/microsoft",async(HttpContext context)=>
{
    if(!microsoftAuthEnabled)
    {
        return (IResult)Results.NotFound(new{error="Microsoft sign-in is not configured"});
    }

    await context.ChallengeAsync("Microsoft",new AuthenticationProperties{RedirectUri="/"});
    return (IResult)Results.Empty;
}).AllowAnonymous();
api.MapGet("/health",async(AppDbContext db,CancellationToken cancellationToken)=>{try{if(!await db.Database.CanConnectAsync(cancellationToken))return Results.Json(new{status="degraded",database="unavailable"},statusCode:StatusCodes.Status503ServiceUnavailable);return Results.Ok(new{status="ok",database="ok"});}catch{return Results.Json(new{status="degraded",database="unavailable"},statusCode:StatusCodes.Status503ServiceUnavailable);}});
api.MapPost("/auth/login",async(LoginRequest r,SignInManager<ApplicationUser> sm,UserManager<ApplicationUser> users,AppDbContext db,HttpContext ctx)=>{var email=r.Email?.Trim();
if(string.IsNullOrWhiteSpace(email)||string.IsNullOrWhiteSpace(r.Password)){return Results.BadRequest(new{error="Email and password are required"});
}var user=await users.FindByEmailAsync(email);
var result=user is null?SignInResult.Failed:await sm.PasswordSignInAsync(user,r.Password,isPersistent:true,lockoutOnFailure:true);
db.AuditLogs.Add(new(){Action="USER_LOGIN",EntityType="User",EntityId=email,IpAddress=ctx.Connection.RemoteIpAddress?.ToString(),Result=result.Succeeded?"Success":result.IsLockedOut?"LockedOut":"Failure"});
await db.SaveChangesAsync();
if(result.IsLockedOut)return Results.Json(new{error="This account is temporarily locked. Try again in a few minutes."},statusCode:StatusCodes.Status423Locked);
if(!result.Succeeded)return Results.Unauthorized();
 return Results.Ok(new{email=user!.Email,roles=await users.GetRolesAsync(user)});
 }).RequireRateLimiting("auth");
api.MapPost("/auth/logout",async(SignInManager<ApplicationUser> sm)=>{await sm.SignOutAsync();
return Results.NoContent();
}).RequireAuthorization();
api.MapPost("/auth/password",async(ChangePasswordInput r,UserManager<ApplicationUser> users,ClaimsPrincipal actor,AppDbContext db)=>{if(string.IsNullOrWhiteSpace(r.CurrentPassword)||string.IsNullOrWhiteSpace(r.NewPassword)||r.NewPassword.Length<12)return Results.BadRequest(new{error="Current password is required and the new password must be at least 12 characters"});if(r.NewPassword!=r.ConfirmPassword)return Results.BadRequest(new{error="New passwords do not match"});var id=actor.FindFirstValue(ClaimTypes.NameIdentifier);var user=id is null?null:await users.FindByIdAsync(id);if(user is null)return Results.Unauthorized();var result=await users.ChangePasswordAsync(user,r.CurrentPassword,r.NewPassword);if(!result.Succeeded)return Results.BadRequest(new{error="Current password is incorrect or the new password does not meet policy",details=result.Errors.Select(x=>x.Description)});Audit(db,actor,"CHANGE_PASSWORD","User",user.Id);await db.SaveChangesAsync();return Results.NoContent();}).RequireAuthorization();
api.MapGet("/me",(ClaimsPrincipal u)=>Results.Ok(new{email=u.Identity!.Name,roles=u.Claims.Where(x=>x.Type==ClaimTypes.Role).Select(x=>x.Value)})).RequireAuthorization();
api.MapGet("/admin/users",async(UserManager<ApplicationUser> users)=>{var records=await users.Users.OrderBy(x=>x.Email).ToListAsync();var result=new List<object>();foreach(var user in records)result.Add(new{user.Id,user.Email,user.DisplayName,user.EmailConfirmed,user.LockoutEnd,roles=await users.GetRolesAsync(user)});return Results.Ok(result);}).RequireAuthorization("Admin");
api.MapPost("/admin/users",async(AdminUserInput r,UserManager<ApplicationUser> users,ClaimsPrincipal actor,AppDbContext db)=>{if(string.IsNullOrWhiteSpace(r.Email)||r.Email.Length>320||!System.Net.Mail.MailAddress.TryCreate(r.Email.Trim(),out _ )||string.IsNullOrWhiteSpace(r.Password)||r.Password.Length<12||r.DisplayName is {Length:>200})return Results.BadRequest(new{error="Enter a valid email, display name, and a password of at least 12 characters"});var email=r.Email.Trim().ToLowerInvariant();if(await users.FindByEmailAsync(email) is not null)return Results.Conflict(new{error="A user with that email already exists"});var user=new ApplicationUser{UserName=email,Email=email,DisplayName=string.IsNullOrWhiteSpace(r.DisplayName)?email:r.DisplayName.Trim(),EmailConfirmed=true};var result=await users.CreateAsync(user,r.Password);if(!result.Succeeded)return Results.BadRequest(new{error=string.Join("; ",result.Errors.Select(x=>x.Description))});var role=r.Role is Roles.Reader or Roles.Operator or Roles.Administrator?r.Role:Roles.Reader;var roleResult=await users.AddToRoleAsync(user,role);if(!roleResult.Succeeded){await users.DeleteAsync(user);return Results.BadRequest(new{error=string.Join("; ",roleResult.Errors.Select(x=>x.Description))});}Audit(db,actor,"CREATE_USER","User",user.Id);await db.SaveChangesAsync();return Results.Created($"/api/admin/users/{user.Id}",new{user.Id,user.Email,user.DisplayName,role});}).RequireAuthorization("Admin");
api.MapPost("/admin/users/{id}/lock",async(string id,UserManager<ApplicationUser> users,ClaimsPrincipal actor,AppDbContext db)=>{var user=await users.FindByIdAsync(id);if(user is null)return Results.NotFound();if(user.Id==actor.FindFirstValue(ClaimTypes.NameIdentifier)&&user.LockoutEnd is null)return Results.BadRequest(new{error="You cannot lock your own account"});user.LockoutEnd=user.LockoutEnd is null?DateTimeOffset.UtcNow.AddYears(10):null;var result=await users.UpdateAsync(user);if(!result.Succeeded)return Results.BadRequest(new{error=string.Join("; ",result.Errors.Select(x=>x.Description))});Audit(db,actor,user.LockoutEnd is null?"UNLOCK_USER":"LOCK_USER","User",user.Id);await db.SaveChangesAsync();return Results.NoContent();}).RequireAuthorization("Admin");
api.MapPut("/admin/users/{id}/role",async(string id,AdminRoleInput r,UserManager<ApplicationUser> users,ClaimsPrincipal actor,AppDbContext db)=>{if(r.Role is not (Roles.Reader or Roles.Operator or Roles.Administrator))return Results.BadRequest(new{error="Role must be Reader, CertificateOperator, or Administrator"});var user=await users.FindByIdAsync(id);if(user is null)return Results.NotFound();var current=await users.GetRolesAsync(user);if(current.Contains(Roles.Administrator)&&r.Role!=Roles.Administrator){var administrators=await users.GetUsersInRoleAsync(Roles.Administrator);if(administrators.Count<=1)return Results.BadRequest(new{error="At least one administrator must remain"});if(user.Id==actor.FindFirstValue(ClaimTypes.NameIdentifier))return Results.BadRequest(new{error="You cannot remove your own administrator access"});}var removed=await users.RemoveFromRolesAsync(user,current);if(!removed.Succeeded)return Results.BadRequest(new{error=string.Join("; ",removed.Errors.Select(x=>x.Description))});var added=await users.AddToRoleAsync(user,r.Role);if(!added.Succeeded)return Results.BadRequest(new{error=string.Join("; ",added.Errors.Select(x=>x.Description))});Audit(db,actor,"UPDATE_USER_ROLE","User",user.Id);await db.SaveChangesAsync();return Results.Ok(new{user.Id,role=r.Role});}).RequireAuthorization("Admin");
api.MapPost("/admin/users/{id}/password",async(string id,AdminPasswordResetInput r,UserManager<ApplicationUser> users,ClaimsPrincipal actor,AppDbContext db)=>{if(string.IsNullOrWhiteSpace(r.Password)||r.Password.Length<12)return Results.BadRequest(new{error="Password must be at least 12 characters"});var user=await users.FindByIdAsync(id);if(user is null)return Results.NotFound();var token=await users.GeneratePasswordResetTokenAsync(user);var result=await users.ResetPasswordAsync(user,token,r.Password);if(!result.Succeeded)return Results.BadRequest(new{error=string.Join("; ",result.Errors.Select(x=>x.Description))});user.LockoutEnd=null;var updated=await users.UpdateAsync(user);if(!updated.Succeeded)return Results.BadRequest(new{error=string.Join("; ",updated.Errors.Select(x=>x.Description))});Audit(db,actor,"RESET_USER_PASSWORD","User",user.Id);await db.SaveChangesAsync();return Results.NoContent();}).RequireAuthorization("Admin");
api.MapGet("/admin/integrations",(IOptionsMonitor<SmtpOptions> smtp)=>{var value=smtp.CurrentValue;return Results.Ok(new{api=new{openApi=app.Environment.IsDevelopment(),basePath="/api",authentication="ASP.NET Core Identity cookie"},mail=new{value.Enabled,value.Host,value.Port,value.From,username=value.Username,configured=value.Enabled&&!string.IsNullOrWhiteSpace(value.Host)&&!string.IsNullOrWhiteSpace(value.From),credentialsConfigured=!string.IsNullOrWhiteSpace(value.Username)&&!string.IsNullOrWhiteSpace(value.Password)}});}).RequireAuthorization("Admin");
api.MapPut("/admin/integrations/mail",async(MailSettingsInput r,AppDbContext db,IOptionsMonitor<SmtpOptions> smtp,IOptionsMonitorCache<SmtpOptions> cache,IDataProtectionProvider protection,ClaimsPrincipal user)=>{if(r.Port is <1 or >65535)return Results.BadRequest(new{error="SMTP port must be between 1 and 65535"});if(r.Enabled&&string.IsNullOrWhiteSpace(r.Host))return Results.BadRequest(new{error="SMTP host is required when mail is enabled"});if(r.Enabled&&string.IsNullOrWhiteSpace(r.From))return Results.BadRequest(new{error="Sender address is required when mail is enabled"});if(!string.IsNullOrWhiteSpace(r.From)&&!System.Net.Mail.MailAddress.TryCreate(r.From.Trim(),out _))return Results.BadRequest(new{error="Sender address is not valid"});var current=smtp.CurrentValue;var row=await db.MailProviderSettings.SingleOrDefaultAsync(x=>x.Id==1);var isNew=row is null;row??=new MailProviderSettings();var password=string.IsNullOrWhiteSpace(r.Password)?current.Password:r.Password;row.Enabled=r.Enabled;row.Host=r.Host?.Trim()??"";row.Port=r.Port;row.Username=r.Username?.Trim()??"";row.From=r.From?.Trim()??"";if(!string.IsNullOrWhiteSpace(r.Password))row.ProtectedPassword=protection.CreateProtector("CertificateManager.MailProviderPassword.v1").Protect(r.Password);else if(string.IsNullOrWhiteSpace(row.ProtectedPassword)&&!string.IsNullOrWhiteSpace(current.Password))row.ProtectedPassword=protection.CreateProtector("CertificateManager.MailProviderPassword.v1").Protect(current.Password);row.UpdatedAt=DateTimeOffset.UtcNow;if(isNew)db.MailProviderSettings.Add(row);Audit(db,user,"UPDATE_MAIL_SETTINGS","MailProviderSettings",row.Id);await db.SaveChangesAsync();var updated=new SmtpOptions{Enabled=row.Enabled,Host=row.Host,Port=row.Port,Username=row.Username,Password=password,From=row.From};cache.TryRemove(Options.DefaultName);cache.TryAdd(Options.DefaultName,updated);return Results.Ok(new{updated.Enabled,updated.Host,updated.Port,updated.From,username=updated.Username,configured=updated.Enabled&&!string.IsNullOrWhiteSpace(updated.Host)&&!string.IsNullOrWhiteSpace(updated.From),credentialsConfigured=!string.IsNullOrWhiteSpace(updated.Username)&&!string.IsNullOrWhiteSpace(updated.Password)});}).RequireAuthorization("Admin");
api.MapPost("/admin/integrations/mail/test",async(MailTestInput r,IOptionsMonitor<SmtpOptions> smtp,INotificationService mail)=>{if(string.IsNullOrWhiteSpace(r.Recipient)||!System.Net.Mail.MailAddress.TryCreate(r.Recipient.Trim(),out _))return Results.BadRequest(new{error="Enter a valid test recipient"});if(!smtp.CurrentValue.Enabled)return Results.BadRequest(new{error="Enable SMTP before sending a test message"});try{await mail.SendAsync(r.Recipient.Trim(),"Certificate Manager SMTP test","This message confirms that the configured mail provider is working.",CancellationToken.None);return Results.Ok(new{message="Test message sent"});}catch{return Results.BadRequest(new{error="SMTP test failed. Check the host, port, credentials, and sender address."});}}).RequireAuthorization("Admin");
api.MapGet("/admin/notifications",async(IOptionsMonitor<NotificationOptions> options,AppDbContext db)=>{var settings=options.CurrentValue;var last=await db.NotificationHistory.AsNoTracking().OrderByDescending(x=>x.SentAt).Select(x=>(DateTimeOffset?)x.SentAt).FirstOrDefaultAsync();return Results.Ok(new{settings.Enabled,settings.InitialDelaySeconds,settings.IntervalHours,milestones=settings.Milestones,lastSentAt=last});}).RequireAuthorization("Admin");
api.MapPut("/admin/notifications",async(NotificationSettingsInput r,AppDbContext db,IOptionsMonitorCache<NotificationOptions> cache,ClaimsPrincipal user)=>{if(r.InitialDelaySeconds is <5 or >3600)return Results.BadRequest(new{error="Initial delay must be between 5 seconds and 1 hour"});if(r.IntervalHours is <1 or >168)return Results.BadRequest(new{error="Interval must be between 1 and 168 hours"});var milestones=(r.Milestones??Array.Empty<int>()).Where(x=>x>=0&&x<=365).Distinct().OrderByDescending(x=>x).ToArray();if(milestones.Length==0||milestones.Length>12)return Results.BadRequest(new{error="Choose between 1 and 12 renewal milestones from 0 to 365 days"});var row=await db.NotificationSettings.SingleOrDefaultAsync(x=>x.Id==1);var isNew=row is null;row??=new NotificationSettings();row.Enabled=r.Enabled;row.InitialDelaySeconds=r.InitialDelaySeconds;row.IntervalHours=r.IntervalHours;row.Milestones=string.Join(',',milestones);row.UpdatedAt=DateTimeOffset.UtcNow;if(isNew)db.NotificationSettings.Add(row);Audit(db,user,"UPDATE_NOTIFICATION_SETTINGS","NotificationSettings",row.Id);await db.SaveChangesAsync();var updated=new NotificationOptions{Enabled=row.Enabled,InitialDelaySeconds=row.InitialDelaySeconds,IntervalHours=row.IntervalHours,Milestones=milestones};cache.TryRemove(Options.DefaultName);cache.TryAdd(Options.DefaultName,updated);var last=await db.NotificationHistory.AsNoTracking().OrderByDescending(x=>x.SentAt).Select(x=>(DateTimeOffset?)x.SentAt).FirstOrDefaultAsync();return Results.Ok(new{updated.Enabled,updated.InitialDelaySeconds,updated.IntervalHours,milestones=updated.Milestones,lastSentAt=last});}).RequireAuthorization("Admin");
api.MapGet("/customers",async(AppDbContext db)=>await db.Customers.AsNoTracking().OrderBy(x=>x.Name).ToListAsync()).RequireAuthorization("Read");
api.MapPost("/customers",async(CustomerInput r,AppDbContext db,ClaimsPrincipal u)=>{if(string.IsNullOrWhiteSpace(r.Name)||r.Name.Length>200||r.Description is {Length:>2000}||r.CustomerNumber is {Length:>100})return Results.BadRequest(new{error="Customer name, description, and customer number exceed the allowed length"});
var c=new Customer{Name=r.Name.Trim(),Description=r.Description??"",CustomerNumber=r.CustomerNumber};
db.Customers.Add(c);
Audit(db,u,"CREATE_CUSTOMER","Customer",c.Id);
await db.SaveChangesAsync();
return Results.Created($"/api/customers/{c.Id}",c);
}).RequireAuthorization("Admin");
api.MapPut("/customers/{id:guid}",async(Guid id,CustomerInput r,AppDbContext db,ClaimsPrincipal u)=>{if(string.IsNullOrWhiteSpace(r.Name)||r.Name.Length>200||r.Description is {Length:>2000}||r.CustomerNumber is {Length:>100})return Results.BadRequest(new{error="Customer name, description, and customer number exceed the allowed length"});var customer=await db.Customers.FindAsync(id);if(customer is null)return Results.NotFound();customer.Name=r.Name.Trim();customer.Description=r.Description?.Trim()??"";customer.CustomerNumber=string.IsNullOrWhiteSpace(r.CustomerNumber)?null:r.CustomerNumber.Trim();customer.UpdatedAt=DateTimeOffset.UtcNow;Audit(db,u,"UPDATE_CUSTOMER","Customer",customer.Id);await db.SaveChangesAsync();return Results.Ok(customer);}).RequireAuthorization("Admin");
api.MapPost("/customers/{id:guid}/status",async(Guid id,StatusInput r,AppDbContext db,ClaimsPrincipal u)=>{var customer=await db.Customers.FindAsync(id);if(customer is null)return Results.NotFound();customer.IsActive=r.Active;customer.UpdatedAt=DateTimeOffset.UtcNow;Audit(db,u,r.Active?"RESTORE_CUSTOMER":"ARCHIVE_CUSTOMER","Customer",customer.Id);await db.SaveChangesAsync();return Results.Ok(new{customer.Id,customer.IsActive});}).RequireAuthorization("Admin");
api.MapGet("/environments",async(Guid? customerId,AppDbContext db)=>await db.Environments.AsNoTracking().Where(x=>customerId==null||x.CustomerId==customerId).OrderBy(x=>x.Name).ToListAsync()).RequireAuthorization("Read");
api.MapPost("/environments",async(EnvironmentInput r,AppDbContext db,ClaimsPrincipal u)=>{if(string.IsNullOrWhiteSpace(r.Name)||r.Name.Length>200||r.Description is {Length:>2000}||r.TenantReference is {Length:>200}||!Enum.IsDefined(r.EnvironmentType))return Results.BadRequest(new{error="Environment fields are invalid or exceed the allowed length"});
if(!await db.Customers.AnyAsync(x=>x.Id==r.CustomerId&&x.IsActive))return Results.BadRequest(new{error="Customer not found"});
var e=new TargetEnvironment{CustomerId=r.CustomerId,Name=r.Name.Trim(),Description=r.Description??"",TenantReference=r.TenantReference,EnvironmentType=r.EnvironmentType};
db.Environments.Add(e);
Audit(db,u,"CREATE_ENVIRONMENT","Environment",e.Id);
await db.SaveChangesAsync();
return Results.Created($"/api/environments/{e.Id}",e);
}).RequireAuthorization("Admin");
api.MapGet("/services",async(Guid? customerId,AppDbContext db)=>await db.Services.AsNoTracking().Include(x=>x.Environment).ThenInclude(x=>x.Customer).Where(x=>customerId==null||x.Environment.CustomerId==customerId).OrderBy(x=>x.Name).Select(x=>new{x.Id,x.Name,x.Description,x.ApplicationClientId,x.ExternalReference,x.IsActive,certificateReady=!string.IsNullOrWhiteSpace(x.ApplicationClientId),customerId=x.Environment.CustomerId,customer=x.Environment.Customer.Name}).ToListAsync()).RequireAuthorization("Read");
api.MapPost("/services",async(ServiceInput r,AppDbContext db,ClaimsPrincipal u)=>{if(string.IsNullOrWhiteSpace(r.Name)||r.Name.Length>200||r.Description is {Length:>2000}||r.ApplicationClientId is {Length:>200}||r.ExternalReference is {Length:>200})return Results.BadRequest(new{error="Service name, description, and references exceed the allowed length"});
var customer=await db.Customers.SingleOrDefaultAsync(x=>x.Id==r.CustomerId&&x.IsActive);
if(customer is null)return Results.BadRequest(new{error="Customer not found"});
var environment=await db.Environments.SingleOrDefaultAsync(x=>x.CustomerId==r.CustomerId&&x.Name=="Default");
if(environment is null){environment=new TargetEnvironment{CustomerId=r.CustomerId,Name="Default",Description="Managed automatically"};db.Environments.Add(environment);}
var s=new ManagedService{Environment=environment,Name=r.Name.Trim(),Description=r.Description??"",ApplicationClientId=r.ApplicationClientId,ExternalReference=r.ExternalReference};
db.Services.Add(s);
Audit(db,u,"CREATE_SERVICE","Service",s.Id);
await db.SaveChangesAsync();
return Results.Created($"/api/services/{s.Id}",s);
}).RequireAuthorization("Admin");
api.MapPut("/services/{id:guid}",async(Guid id,ServiceUpdateInput r,AppDbContext db,ClaimsPrincipal u)=>{if(string.IsNullOrWhiteSpace(r.Name)||r.Name.Length>200||r.Description is {Length:>2000}||r.ApplicationClientId is {Length:>200}||r.ExternalReference is {Length:>200})return Results.BadRequest(new{error="Service name, description, and references exceed the allowed length"});var service=await db.Services.FindAsync(id);if(service is null)return Results.NotFound();service.Name=r.Name.Trim();service.Description=r.Description?.Trim()??"";service.ApplicationClientId=string.IsNullOrWhiteSpace(r.ApplicationClientId)?null:r.ApplicationClientId.Trim();service.ExternalReference=string.IsNullOrWhiteSpace(r.ExternalReference)?null:r.ExternalReference.Trim();service.UpdatedAt=DateTimeOffset.UtcNow;Audit(db,u,"UPDATE_SERVICE","Service",service.Id);await db.SaveChangesAsync();return Results.Ok(service);}).RequireAuthorization("Admin");
api.MapPost("/services/{id:guid}/status",async(Guid id,StatusInput r,AppDbContext db,ClaimsPrincipal u)=>{var service=await db.Services.FindAsync(id);if(service is null)return Results.NotFound();service.IsActive=r.Active;service.UpdatedAt=DateTimeOffset.UtcNow;Audit(db,u,r.Active?"RESTORE_SERVICE":"ARCHIVE_SERVICE","Service",service.Id);await db.SaveChangesAsync();return Results.Ok(new{service.Id,service.IsActive});}).RequireAuthorization("Admin");
api.MapGet("/certificates",async(string? search,string? health,string? sort,string? direction,int page,int pageSize,AppDbContext db)=>{page=Math.Clamp(page,1,1000000);
pageSize=Math.Clamp(pageSize==0?25:pageSize,1,100);
 var q=db.Certificates.AsNoTracking().Where(x=>x.Status!=CertificateStatus.Decommissioned).Include(x=>x.Service).ThenInclude(x=>x.Environment).ThenInclude(x=>x.Customer).Where(x=>string.IsNullOrEmpty(search)||x.Name.Contains(search)||x.Thumbprint.Contains(search)||x.PrimaryOwnerEmail.Contains(search)||x.Service.Name.Contains(search)||x.Service.Environment.Customer.Name.Contains(search));
var now=DateTimeOffset.UtcNow;
q=health switch{"Healthy"=>q.Where(x=>x.ValidUntil>now.AddDays(60)),"RenewalUpcoming"=>q.Where(x=>x.ValidUntil>now.AddDays(30)&&x.ValidUntil<=now.AddDays(60)),"RenewalRequired"=>q.Where(x=>x.ValidUntil>now.AddDays(14)&&x.ValidUntil<=now.AddDays(30)),"Critical"=>q.Where(x=>x.ValidUntil>now&&x.ValidUntil<=now.AddDays(14)),"Expired"=>q.Where(x=>x.ValidUntil<=now),_=>q};
var total=await q.CountAsync();
var descending=string.Equals(direction,"desc",StringComparison.OrdinalIgnoreCase);
q=(sort?.ToLowerInvariant(),descending) switch{("name",false)=>q.OrderBy(x=>x.Name),("name",true)=>q.OrderByDescending(x=>x.Name),("customer",false)=>q.OrderBy(x=>x.Service.Environment.Customer.Name),("customer",true)=>q.OrderByDescending(x=>x.Service.Environment.Customer.Name),("owner",false)=>q.OrderBy(x=>x.PrimaryOwnerEmail),("owner",true)=>q.OrderByDescending(x=>x.PrimaryOwnerEmail),("validuntil",true)=>q.OrderByDescending(x=>x.ValidUntil),_=>q.OrderBy(x=>x.ValidUntil)};
var rows=await q.Skip((page-1)*pageSize).Take(pageSize).ToListAsync();
var items=rows.Select(x=>new{x.Id,x.Name,x.Subject,serviceId=x.ServiceId,x.Thumbprint,x.ValidUntil,daysRemaining=(int)Math.Floor((x.ValidUntil-now).TotalDays),health=CertificateHealth.Calculate(x.ValidUntil,now),x.Status,x.PrimaryOwnerEmail,x.DeploymentStatus,service=x.Service.Name,customer=x.Service.Environment.Customer.Name});
return Results.Ok(new{items,total,page,pageSize});
}).RequireAuthorization("Read");
api.MapGet("/certificates/retired",async(AppDbContext db)=>await db.Certificates.AsNoTracking().Where(x=>x.Status==CertificateStatus.Decommissioned).Include(x=>x.Service).ThenInclude(x=>x.Environment).ThenInclude(x=>x.Customer).OrderByDescending(x=>x.DecommissionedAt).Take(50).Select(x=>new{x.Id,x.Name,x.Thumbprint,x.ValidUntil,x.DecommissionedAt,x.DecommissionReason,x.PrimaryOwnerEmail,service=x.Service.Name,customer=x.Service.Environment.Customer.Name}).ToListAsync()).RequireAuthorization("Read");
api.MapGet("/certificates/export", async (string? search, AppDbContext db) =>
{
    var certificates = await db.Certificates
        .AsNoTracking()
        .Where(certificate => certificate.Status != CertificateStatus.Decommissioned)
        .Include(certificate => certificate.Service)
        .ThenInclude(service => service.Environment)
        .ThenInclude(environment => environment.Customer)
        .Where(certificate =>
            string.IsNullOrEmpty(search) ||
            certificate.Name.Contains(search) ||
            certificate.Thumbprint.Contains(search) ||
            certificate.PrimaryOwnerEmail.Contains(search) ||
            certificate.Service.Name.Contains(search) ||
            certificate.Service.Environment.Customer.Name.Contains(search))
        .OrderBy(certificate => certificate.ValidUntil)
        .ToListAsync();

    var csv = new StringBuilder();
    csv.AppendLine("Customer,Service,Certificate,Thumbprint,Valid until,Owner,Health,Status,Deployment");

    foreach (var certificate in certificates)
    {
        csv.AppendLine(string.Join(",",
            Csv(certificate.Service.Environment.Customer.Name),
            Csv(certificate.Service.Name),
            Csv(certificate.Name),
            Csv(certificate.Thumbprint),
            Csv(certificate.ValidUntil.ToString("u")),
            Csv(certificate.PrimaryOwnerEmail),
            Csv(CertificateHealth.Calculate(certificate.ValidUntil, DateTimeOffset.UtcNow)),
            Csv(certificate.Status.ToString()),
            Csv(certificate.DeploymentStatus.ToString())));
    }

    return Results.File(
        Encoding.UTF8.GetBytes(csv.ToString()),
        "text/csv",
        $"certificates-{DateTime.UtcNow:yyyyMMdd}.csv");
}).RequireAuthorization("Read");
api.MapPost("/certificates/generate",async(GenerateCertificateRequest r,AppDbContext db,ICertificateGenerator generator,ClaimsPrincipal user,HttpContext context)=>{if(r.ServiceId==Guid.Empty||string.IsNullOrWhiteSpace(r.Name)||r.Name.Length>200||r.Notes is {Length:>4000}||string.IsNullOrWhiteSpace(r.CommonName)||r.CommonName.Length>255||string.IsNullOrWhiteSpace(r.PrimaryOwnerEmail)||r.PrimaryOwnerEmail.Length>320||!System.Net.Mail.MailAddress.TryCreate(r.PrimaryOwnerEmail.Trim(),out _ )||(!string.IsNullOrEmpty(r.Password)&&r.Password.Length<16)||r.ValidityDays<1||r.ValidityDays>3650||r.RenewalReminderDays<1||r.RenewalReminderDays>r.ValidityDays||r.KeySize is not (2048 or 3072 or 4096)||r.HashAlgorithm is not ("SHA256" or "SHA384" or "SHA512")||!Enum.IsDefined(r.UseCase))return Results.BadRequest(new{error="Service, name, common name, and owner email are required"});
 r=r with{Name=r.Name.Trim(),CommonName=r.CommonName.Trim(),PrimaryOwnerEmail=r.PrimaryOwnerEmail.Trim().ToLowerInvariant(),Notes=string.IsNullOrWhiteSpace(r.Notes)?null:r.Notes.Trim()};
var service=await db.Services.Include(x=>x.Environment).ThenInclude(x=>x.Customer).SingleOrDefaultAsync(x=>x.Id==r.ServiceId&&x.IsActive&&x.Environment.IsActive&&x.Environment.Customer.IsActive);
if(service is null)return Results.NotFound();
 if((r.UseCase is CertificateUseCase.ClientAuthentication or CertificateUseCase.ClientAndServerAuthentication)&&string.IsNullOrWhiteSpace(service.ApplicationClientId))return Results.BadRequest(new{error="Add an Application (client) ID to the service before generating a service-principal certificate"});
var duplicateName=await db.Certificates.AnyAsync(x=>x.ServiceId==r.ServiceId&&x.Name==r.Name.Trim()&&x.Status!=CertificateStatus.Decommissioned&&x.Status!=CertificateStatus.Renewed&&x.Status!=CertificateStatus.Superseded&&x.Id!=r.PreviousCertificateId);
if(duplicateName)return Results.Conflict(new{error="An active certificate with that name already exists for this service"});
var generated=generator.Generate(r,user.FindFirstValue(ClaimTypes.NameIdentifier)!,service.Environment.Customer.Name,service.Environment.Name,service.Name,service.ApplicationClientId);
db.Certificates.Add(generated.Metadata);
if(r.PreviousCertificateId is Guid previous){var old=await db.Certificates.FindAsync(previous);
if(old is null)return Results.BadRequest(new{error="Previous certificate not found"});
if(old.ServiceId!=r.ServiceId)return Results.BadRequest(new{error="The previous certificate belongs to another service"});
if(old.Status is CertificateStatus.Decommissioned or CertificateStatus.Superseded or CertificateStatus.Renewed)return Results.BadRequest(new{error="The previous certificate has already been replaced or decommissioned"});
old.ReplacementCertificateId=generated.Metadata.Id;
old.Status=CertificateStatus.Renewed;
old.DeploymentStatus=DeploymentStatus.Superseded;
}Audit(db,user,r.PreviousCertificateId is null?"CREATE_CERTIFICATE":"RENEW_CERTIFICATE","Certificate",generated.Metadata.Id);
 await db.SaveChangesAsync();
 context.Response.Headers.CacheControl="no-store";
 context.Response.Headers.Pragma="no-cache";
return Results.Ok(new{generated.Metadata.Id,generated.Metadata.Name,generated.Metadata.Thumbprint,generated.Metadata.ValidUntil,generated.Metadata.RenewalDueAt,password=generated.Password,pfx=Convert.ToBase64String(generated.Pfx),cer=Convert.ToBase64String(generated.Cer),calendar=Convert.ToBase64String(generated.Calendar),package=Convert.ToBase64String(generated.Package)});
}).RequireAuthorization("Operate");
api.MapGet("/certificates/{id:guid}",async(Guid id,AppDbContext db)=>{var c=await db.Certificates.AsNoTracking().Include(x=>x.Service).ThenInclude(x=>x.Environment).ThenInclude(x=>x.Customer).SingleOrDefaultAsync(x=>x.Id==id);
if(c is null)return Results.NotFound();
var detail=new{c.Id,c.Name,c.Subject,c.Issuer,c.Thumbprint,c.SerialNumber,c.Algorithm,c.KeySize,c.HashAlgorithm,c.ValidFrom,c.ValidUntil,c.RenewalDueAt,c.CreatedByUserId,c.PrimaryOwnerEmail,c.Status,c.PreviousCertificateId,c.ReplacementCertificateId,c.DeploymentStatus,c.DeploymentConfirmedAt,c.DeploymentConfirmedByUserId,c.Notes,c.DecommissionedAt,c.DecommissionedByUserId,c.DecommissionReason,c.ServiceId,service=c.Service.Name,customer=c.Service.Environment.Customer.Name};
return Results.Ok(new{certificate=detail,health=CertificateHealth.Calculate(c.ValidUntil,DateTimeOffset.UtcNow),privateKeyAvailable=false});
}).RequireAuthorization("Read");
api.MapPost("/certificates/{id:guid}/mark-deployed",async(Guid id,AppDbContext db,ClaimsPrincipal u)=>{var c=await db.Certificates.FindAsync(id);
 if(c is null)return Results.NotFound();
 if(c.Status is CertificateStatus.Decommissioned or CertificateStatus.Superseded or CertificateStatus.Renewed)return Results.BadRequest(new{error="Historical or decommissioned certificates cannot be deployed"});
c.DeploymentStatus=DeploymentStatus.DeploymentConfirmed;
c.DeploymentConfirmedAt=DateTimeOffset.UtcNow;
c.DeploymentConfirmedByUserId=u.FindFirstValue(ClaimTypes.NameIdentifier);
Audit(db,u,"MARK_DEPLOYED","Certificate",id);
await db.SaveChangesAsync();
return Results.NoContent();
}).RequireAuthorization("Operate");
api.MapPost("/certificates/{id:guid}/decommission",async(Guid id,DecommissionInput r,AppDbContext db,ClaimsPrincipal u)=>{if(r.Reason is {Length:>1000})return Results.BadRequest(new{error="Retirement reason must be 1000 characters or fewer"});var c=await db.Certificates.FindAsync(id);
 if(c is null)return Results.NotFound();
 if(c.Status is CertificateStatus.Decommissioned or CertificateStatus.Superseded or CertificateStatus.Renewed)return Results.BadRequest(new{error="Historical certificates cannot be decommissioned again"});
 c.Status=CertificateStatus.Decommissioned;
 c.DecommissionedAt=DateTimeOffset.UtcNow;
 c.DecommissionedByUserId=u.FindFirstValue(ClaimTypes.NameIdentifier);
 c.DecommissionReason=string.IsNullOrWhiteSpace(r.Reason)?null:r.Reason.Trim();
Audit(db,u,"DECOMMISSION_CERTIFICATE","Certificate",id);
await db.SaveChangesAsync();
return Results.NoContent();
}).RequireAuthorization("Admin");
api.MapGet("/certificates/{id:guid}/calendar",async(Guid id,AppDbContext db)=>{var c=await db.Certificates.Include(x=>x.Service).ThenInclude(x=>x.Environment).ThenInclude(x=>x.Customer).SingleOrDefaultAsync(x=>x.Id==id&&x.Status!=CertificateStatus.Decommissioned);
return c is null?Results.NotFound():Results.File(CalendarGenerator.Generate(c,c.Service.Environment.Customer.Name,c.Service.Environment.Name,c.Service.Name),"text/calendar",$"{c.Name}-renewal.ics");
}).RequireAuthorization("Read");
api.MapGet("/dashboard",async(AppDbContext db)=>{var now=DateTimeOffset.UtcNow;
var dates=await db.Certificates.Where(x=>x.Status!=CertificateStatus.Decommissioned&&x.Status!=CertificateStatus.Superseded&&x.Status!=CertificateStatus.Renewed).Select(x=>x.ValidUntil).ToListAsync();
return Results.Ok(new{total=dates.Count,healthy=dates.Count(x=>(x-now).TotalDays>60),expiring60=dates.Count(x=>(x-now).TotalDays is >30 and <=60),expiring30=dates.Count(x=>(x-now).TotalDays is >14 and <=30),expiring14=dates.Count(x=>(x-now).TotalDays is >7 and <=14),critical=dates.Count(x=>(x-now).TotalDays is >0 and <=7),expired=dates.Count(x=>x<=now)});
}).RequireAuthorization("Read");
api.MapGet("/audit",async(string? search,int? limit,AppDbContext db)=>{var take=Math.Clamp(limit??200,1,500);var query=db.AuditLogs.AsNoTracking();if(!string.IsNullOrWhiteSpace(search)){var term=search.Trim();query=query.Where(x=>x.Action.Contains(term)||x.EntityType.Contains(term)||(x.EntityId!=null&&x.EntityId.Contains(term))||x.Result.Contains(term));}return Results.Ok(await query.OrderByDescending(x=>x.Timestamp).Take(take).ToListAsync());}).RequireAuthorization("Admin");
app.MapFallback(async context=>{if(context.Request.Path.StartsWithSegments("/api")){context.Response.StatusCode=StatusCodes.Status404NotFound;
return;
}context.Response.ContentType="text/html; charset=utf-8";
await context.Response.SendFileAsync(Path.Combine(app.Environment.WebRootPath??"wwwroot","index.html"));
});
await SeedAsync(app.Services,app.Environment);
await app.RunAsync();
static string Csv(string? value) =>
    $"\"{CsvSafe(value).Replace("\"", "\"\"")}\"";
static string CsvSafe(string? value)
{
    var text = value ?? string.Empty;
    return text.Length > 0 && (text[0] is '=' or '+' or '-' or '@')
        ? "'" + text
        : text;
}
static void Audit(AppDbContext db,ClaimsPrincipal u,string action,string entity,object id)=>db.AuditLogs.Add(new(){Action=action,EntityType=entity,EntityId=id.ToString(),UserId=u.FindFirstValue(ClaimTypes.NameIdentifier),Result="Success"});
static string TryUnprotectPassword(IDataProtectionProvider protection,string value,string fallback){try{return protection.CreateProtector("CertificateManager.MailProviderPassword.v1").Unprotect(value);}catch{return fallback;}}
static async Task SeedAsync(IServiceProvider services,IHostEnvironment environment){using var scope=services.CreateScope();
 var db=scope.ServiceProvider.GetRequiredService<AppDbContext>();
 if(environment.IsProduction())
 {
  await db.Database.MigrateAsync();
 }
 else
 {
  await db.Database.EnsureCreatedAsync();
  await db.Database.ExecuteSqlRawAsync("CREATE TABLE IF NOT EXISTS \"MailProviderSettings\" (\"Id\" integer NOT NULL PRIMARY KEY, \"Enabled\" boolean NOT NULL, \"Host\" text NOT NULL, \"Port\" integer NOT NULL, \"Username\" text NOT NULL, \"ProtectedPassword\" text NOT NULL, \"From\" text NOT NULL, \"UpdatedAt\" timestamp with time zone NOT NULL);");
  await db.Database.ExecuteSqlRawAsync("CREATE TABLE IF NOT EXISTS \"NotificationSettings\" (\"Id\" integer NOT NULL PRIMARY KEY, \"Enabled\" boolean NOT NULL, \"InitialDelaySeconds\" integer NOT NULL, \"IntervalHours\" integer NOT NULL, \"Milestones\" text NOT NULL, \"UpdatedAt\" timestamp with time zone NOT NULL);");
  await db.Database.ExecuteSqlRawAsync("ALTER TABLE \"Certificates\" ADD COLUMN IF NOT EXISTS \"DecommissionedAt\" timestamp with time zone;");
  await db.Database.ExecuteSqlRawAsync("ALTER TABLE \"Certificates\" ADD COLUMN IF NOT EXISTS \"DecommissionedByUserId\" text;");
  await db.Database.ExecuteSqlRawAsync("ALTER TABLE \"Certificates\" ADD COLUMN IF NOT EXISTS \"DecommissionReason\" text;");
 }
 var storedMail=await db.MailProviderSettings.AsNoTracking().SingleOrDefaultAsync(x=>x.Id==1);
 if(storedMail is not null){var configured=scope.ServiceProvider.GetRequiredService<IOptions<SmtpOptions>>().Value;var mailPassword=string.IsNullOrWhiteSpace(storedMail.ProtectedPassword)?configured.Password:TryUnprotectPassword(scope.ServiceProvider.GetRequiredService<IDataProtectionProvider>(),storedMail.ProtectedPassword,configured.Password);var cache=scope.ServiceProvider.GetRequiredService<IOptionsMonitorCache<SmtpOptions>>();cache.TryRemove(Options.DefaultName);cache.TryAdd(Options.DefaultName,new SmtpOptions{Enabled=storedMail.Enabled,Host=storedMail.Host,Port=storedMail.Port,Username=storedMail.Username,Password=mailPassword,From=storedMail.From});}
 var storedNotifications=await db.NotificationSettings.AsNoTracking().SingleOrDefaultAsync(x=>x.Id==1);
 if(storedNotifications is not null){var milestones=storedNotifications.Milestones.Split(',',StringSplitOptions.RemoveEmptyEntries).Select(x=>int.TryParse(x,out var value)?value:-1).Where(x=>x>=0&&x<=365).Distinct().OrderByDescending(x=>x).ToArray();if(milestones.Length>0){var cache=scope.ServiceProvider.GetRequiredService<IOptionsMonitorCache<NotificationOptions>>();cache.TryRemove(Options.DefaultName);cache.TryAdd(Options.DefaultName,new NotificationOptions{Enabled=storedNotifications.Enabled,InitialDelaySeconds=storedNotifications.InitialDelaySeconds,IntervalHours=storedNotifications.IntervalHours,Milestones=milestones});}}
var roles=scope.ServiceProvider.GetRequiredService<RoleManager<IdentityRole>>();
foreach(var role in new[]{Roles.Reader,Roles.Operator,Roles.Administrator})if(!await roles.RoleExistsAsync(role))await roles.CreateAsync(new(role));
var users=scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();
var email="admin@localhost";
 var password=Environment.GetEnvironmentVariable("SEED_ADMIN_PASSWORD")??(Environment.GetEnvironmentVariable("ASPNETCORE_ENVIRONMENT")=="Production"?throw new InvalidOperationException("SEED_ADMIN_PASSWORD is required in production."):"ChangeMe!123456");
 var resetExisting=string.Equals(Environment.GetEnvironmentVariable("SEED_ADMIN_RESET_PASSWORD"),"true",StringComparison.OrdinalIgnoreCase);
 if(string.IsNullOrWhiteSpace(password)||password.Length<12)throw new InvalidOperationException("SEED_ADMIN_PASSWORD must be at least 12 characters.");
var user=await users.FindByEmailAsync(email);
if(user is null){user=new ApplicationUser{UserName=email,Email=email,DisplayName="Local Administrator",EmailConfirmed=true,LockoutEnabled=true};
var result=await users.CreateAsync(user,password);
if(!result.Succeeded)throw new InvalidOperationException(string.Join("; ",result.Errors.Select(x=>x.Description)));
 }else{user.EmailConfirmed=true;
 user.LockoutEnd=null;
 user.UserName=email;
 await users.UpdateAsync(user);
 if(resetExisting&&!await users.CheckPasswordAsync(user,password)){var token=await users.GeneratePasswordResetTokenAsync(user);
var result=await users.ResetPasswordAsync(user,token,password);
if(!result.Succeeded)throw new InvalidOperationException(string.Join("; ",result.Errors.Select(x=>x.Description)));
}}var assigned=await users.GetRolesAsync(user);
if(!assigned.Contains(Roles.Administrator))await users.AddToRoleAsync(user,Roles.Administrator);
}
 record LoginRequest(string Email,string Password);
 record ChangePasswordInput(string CurrentPassword,string NewPassword,string ConfirmPassword);
 record CustomerInput(string Name,string? Description,string? CustomerNumber);
 record ServiceUpdateInput(string Name,string? Description,string? ApplicationClientId,string? ExternalReference);
 record StatusInput(bool Active);
 record EnvironmentInput(Guid CustomerId,string Name,string? Description,string? TenantReference,EnvironmentType EnvironmentType);
 record ServiceInput(Guid CustomerId,string Name,string? Description,string? ApplicationClientId,string? ExternalReference);
 record AdminUserInput(string Email,string DisplayName,string Password,string Role);
 record AdminRoleInput(string Role);
  record AdminPasswordResetInput(string Password);
  record DecommissionInput(string? Reason);
  record MailSettingsInput(bool Enabled,string Host,int Port,string Username,string? Password,string From);
 record MailTestInput(string Recipient);
 record NotificationSettingsInput(bool Enabled,int InitialDelaySeconds,int IntervalHours,int[]? Milestones);
public partial class Program { }
