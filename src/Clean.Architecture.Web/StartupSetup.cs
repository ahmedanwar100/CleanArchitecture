using System.Security.Claims;
using System.Text;
using Clean.Architecture.Core.Interfaces;
using Clean.Architecture.Core.RoleAggregate;
using Clean.Architecture.Core.UserAggregate;
using Clean.Architecture.Infrastructure.Data;
using Clean.Architecture.SharedKernel.Auth;
using Clean.Architecture.SharedKernel.Utilities;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Identity;
using Microsoft.IdentityModel.Tokens;

namespace Clean.Architecture.Web;

public static class StartupSetup
{
  public static void AddCustomIdentity(this IServiceCollection services, IdentitySettings settings)
  {
    services.AddIdentity<User, Role>(identityOptions =>
    {
      //Password Settings
      identityOptions.Password.RequireDigit = settings.PasswordRequireDigit;
      identityOptions.Password.RequiredLength = settings.PasswordRequiredLength;
      identityOptions.Password.RequireNonAlphanumeric = settings.PasswordRequireNonAlphanumeric; //#@!
      identityOptions.Password.RequireUppercase = settings.PasswordRequireUppercase;
      identityOptions.Password.RequireLowercase = settings.PasswordRequireLowercase;

      //UserName Settings
      identityOptions.User.RequireUniqueEmail = settings.RequireUniqueEmail;
    })
  .AddEntityFrameworkStores<AppDbContext>()
  .AddDefaultTokenProviders();
  }

  public static void AddCustomJwtAuthentication(this IServiceCollection services, JwtSettings settings)
  {
    services.AddAuthentication(options =>
        {
          options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
          options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
          options.DefaultScheme = JwtBearerDefaults.AuthenticationScheme;
        })
      .AddJwtBearer(options =>
       {
         var secretKey = Encoding.UTF8.GetBytes(settings.SecretKey);
         var encryptionKey = Encoding.UTF8.GetBytes(settings.EncryptKey);

         var validationParameters = new TokenValidationParameters
         {
           ClockSkew = TimeSpan.Zero, // default: 5 min
           RequireSignedTokens = true,

           ValidateIssuerSigningKey = true,
           IssuerSigningKey = new SymmetricSecurityKey(secretKey),

           RequireExpirationTime = true,
           ValidateLifetime = true,

           ValidateAudience = true, //default : false
           ValidAudience = settings.Audience,

           ValidateIssuer = true, //default : false
           ValidIssuer = settings.Issuer,

           TokenDecryptionKey = new SymmetricSecurityKey(encryptionKey)
         };

         options.RequireHttpsMetadata = false;
         options.SaveToken = true;
         options.TokenValidationParameters = validationParameters;

         options.Events = new JwtBearerEvents
         {
           OnAuthenticationFailed = context =>
           {
             if (context.Exception != null)
             {
               throw context.Exception;
             }

             return Task.CompletedTask;
           },
           OnTokenValidated = async context =>
           {
             var signInManager = context.HttpContext.RequestServices.GetRequiredService<SignInManager<User>>();
             var userRepository = context.HttpContext.RequestServices.GetRequiredService<IUserRepository>();

             var claimsIdentity = context.Principal?.Identity as ClaimsIdentity;
             if (claimsIdentity?.Claims?.Any() != true)
               context.Fail("This token has no claims.");

             //Find user and token from database and perform your custom validation
             var userId = claimsIdentity?.GetUserId<int>();
             if (userId == null)
               context.Fail("There is no UserId in claims.");

             var user = await userRepository.GetByIdAsync(userId.GetValueOrDefault(), context.HttpContext.RequestAborted);

             if (user == null)
               context.Fail("User not found.");

             if (user != null && !user.IsActive)
               context.Fail("User is not active.");

#pragma warning disable CS8604 // Not Possible null reference argument.
             await userRepository.UpdateLastLoginDateAsync(user, context.HttpContext.RequestAborted);
#pragma warning restore CS8604 // Not Possible null reference argument.
           },
           OnChallenge = context =>
           {
             if (context.AuthenticateFailure != null)
               throw context.AuthenticateFailure;
             //throw new CleanArchAppException(ApiResultStatusCode.UnAuthorized, "Authenticate failure.", HttpStatusCode.Unauthorized, context.AuthenticateFailure, null);
             //throw new CleanArchAppException(ApiResultStatusCode.UnAuthorized, "You are unauthorized to access this resource.", HttpStatusCode.Unauthorized);
             throw new Exception("You are unauthorized to access this resource.");
           }
         };
       });
  }



}
