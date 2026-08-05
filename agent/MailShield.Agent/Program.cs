using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using MailShield.Agent;
using Microsoft.Extensions.Options;

var builder = Host.CreateApplicationBuilder(args);

builder.Services.AddWindowsService(options =>
{
    options.ServiceName = "MailShield Agent";
});

builder.Services.AddOptions<AgentOptions>()
    .Bind(builder.Configuration.GetSection(AgentOptions.SectionName))
    .ValidateOnStart();
builder.Services.AddSingleton(sp =>
{
    var options = sp.GetRequiredService<IOptions<AgentOptions>>().Value;
    options.Validate();
    return options;
});
builder.Services.AddHttpClient<ControlPlaneClient>((serviceProvider, client) =>
{
    var options = serviceProvider.GetRequiredService<AgentOptions>();
    client.BaseAddress = new Uri(options.ControlPlaneUrl);
    client.Timeout = TimeSpan.FromSeconds(15);
});
builder.Services.AddHostedService<AgentWorker>();
builder.Services.AddSingleton<PolicyStore>();
builder.Services.AddSingleton<DlpScanner>();

await builder.Build().RunAsync();
