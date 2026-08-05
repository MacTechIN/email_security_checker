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
builder.Services.AddHostedService<AgentWorker>();

await builder.Build().RunAsync();
