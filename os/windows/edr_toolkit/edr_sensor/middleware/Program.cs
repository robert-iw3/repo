using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.AspNetCore.Authentication.Certificate;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using System.Security.Claims;
using Microsoft.AspNetCore.Server.Kestrel.Https;
using StackExchange.Redis;
using System.IO;

var builder = WebApplication.CreateBuilder(args);

builder.WebHost.ConfigureKestrel(serverOptions => {
    serverOptions.ConfigureHttpsDefaults(listenOptions => {
        listenOptions.ClientCertificateMode = ClientCertificateMode.AllowCertificate;
    });
});

var redisConnectionString = builder.Configuration["Redis:ConnectionString"] ?? "redis.internal:6379";
var multiplexer = ConnectionMultiplexer.Connect(redisConnectionString);
builder.Services.AddSingleton<IConnectionMultiplexer>(multiplexer);

builder.Services.AddAuthentication(CertificateAuthenticationDefaults.AuthenticationScheme)
    .AddCertificate(options => {
        options.AllowedCertificateTypes = CertificateTypes.All;
        options.Events = new CertificateAuthenticationEvents {
            OnCertificateValidated = context => {
                context.Principal = new ClaimsPrincipal(new ClaimsIdentity(context.Principal.Identity.Name));
                context.Success();
                return Task.CompletedTask;
            }
        };
    })
    .AddJwtBearer(options => {
        options.TokenValidationParameters = new Microsoft.IdentityModel.Tokens.TokenValidationParameters {
            ValidateIssuer = true, ValidateAudience = true, ValidateLifetime = true,
        };
    });

builder.Services.AddAuthorization(options => {
    options.AddPolicy("SensorAuthPolicy", policy => {
        policy.AddAuthenticationSchemes(
            CertificateAuthenticationDefaults.AuthenticationScheme,
            JwtBearerDefaults.AuthenticationScheme);
        policy.RequireAuthenticatedUser();
    });
});

builder.Services.AddHostedService<TelemetryRoutingService>();

builder.Services.AddHttpClient("PooledHttp")
    .SetHandlerLifetime(TimeSpan.FromMinutes(5)); // Prevent DNS staleness

builder.Services.AddSingleton<ITelemetrySink, SplunkHecSink>();
builder.Services.AddSingleton<ITelemetrySink, ElasticBulkSink>();
builder.Services.AddSingleton<ITelemetrySink, SqlBulkSink>();

builder.Services.AddHostedService<TelemetryRoutingService>();

var app = builder.Build();

app.UseAuthentication();
app.UseAuthorization();

app.MapPost("/api/v1/telemetry", async (HttpRequest request, IConnectionMultiplexer redis) =>
{
    try {
        using var reader = new StreamReader(request.Body);
        string rawPayload = await reader.ReadToEndAsync();

        if (string.IsNullOrWhiteSpace(rawPayload)) return Results.BadRequest();

        var db = redis.GetDatabase();

        await db.StreamAddAsync("telemetry:ingress", "batch", rawPayload, flags: CommandFlags.FireAndForget);

        return Results.Accepted();
    } catch {
        return Results.StatusCode(500);
    }
}).RequireAuthorization("SensorAuthPolicy");

app.Run();