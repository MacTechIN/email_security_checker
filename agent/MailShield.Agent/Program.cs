using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using MailShield.Agent;

var builder = Host.CreateApplicationBuilder(args);

builder.Services.AddWindowsService(options =>
{
    options.ServiceName = "MailShield Agent";
});

builder.Services.AddHostedService<AgentWorker>();

await builder.Build().RunAsync();
