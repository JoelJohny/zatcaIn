using Microsoft.OpenApi.Models;
// Import your services namespace
using ZatcaIntegration.Services;

var builder = WebApplication.CreateBuilder(args);

// --- 1. Add services to the dependency injection container ---

// Add controllers service to handle API requests.
builder.Services.AddControllers();

// ==> ADD YOUR SERVICES HERE <==
// Registering a service with its interface.
// Scoped means a new instance is created for each web request.
builder.Services.AddScoped<IZatcaService, ZatcaService>();

// Register the new credentials service as a singleton to store credentials for the app's lifetime
builder.Services.AddSingleton<IZatcaCredentialsService, ZatcaCredentialsService>();

// Add Swagger/OpenAPI services for API documentation and testing UI.
// Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen(c =>
{
    c.SwaggerDoc("v1", new OpenApiInfo { Title = "ZatcaIntegration API", Version = "v1" });
});

// Add CORS services to allow cross-origin requests, for example from a front-end application.
builder.Services.AddCors(options =>
{
    options.AddPolicy("AllowAll",
        builder =>
        {
            builder.AllowAnyOrigin()
                   .AllowAnyMethod()
                   .AllowAnyHeader();
        });
});


// --- 2. Build the application ---
var app = builder.Build();


// --- 3. Configure the HTTP request pipeline ---

// Use developer exception page and Swagger UI in the development environment.
if (app.Environment.IsDevelopment())
{
    app.UseDeveloperExceptionPage();
    app.UseSwagger();
    app.UseSwaggerUI(c => c.SwaggerEndpoint("/swagger/v1/swagger.json", "ZatcaIntegration API v1"));
}

// Redirects HTTP requests to HTTPS for security.
app.UseHttpsRedirection();

// Use the CORS policy we defined above.
app.UseCors("AllowAll");

// Enable authorization middleware (can be configured further).
app.UseAuthorization();

// Map attribute-routed controllers to endpoints.
app.MapControllers();


// --- 4. Run the application ---
app.Run();

