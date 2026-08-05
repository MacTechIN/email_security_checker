using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace MailShield.Agent;

public sealed class AgentWorker(ILogger<AgentWorker> logger, AgentOptions options, ControlPlaneClient controlPlaneClient, PolicyStore policyStore) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        logger.LogInformation("MailShield Agent starting at {Time}", DateTimeOffset.UtcNow);

        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                // TODO: load encrypted policy and start provider-specific watchers.
                // IMAP IDLE, Outlook events, DLP and file provenance are separate modules.
                logger.LogDebug("Agent heartbeat at {Time}", DateTimeOffset.UtcNow);
                await controlPlaneClient.SendHeartbeatAsync(options.TenantId, options.DeviceId, stoppingToken);
                var policy = await controlPlaneClient.FetchPolicyAsync(options.TenantId, options.DeviceId, stoppingToken);
                if (policy is not null)
                {
                    policyStore.Save(policy);
                    logger.LogDebug("Policy version {Version} loaded in {Mode} mode", policy.Version, policy.Mode);
                }
                else if (policyStore.Load() is { } cachedPolicy)
                {
                    logger.LogDebug("Using cached policy version {Version} in {Mode} mode", cachedPolicy.Version, cachedPolicy.Mode);
                }
                await Task.Delay(TimeSpan.FromSeconds(options.HeartbeatSeconds), stoppingToken);
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                break;
            }
            catch (Exception exception)
            {
                logger.LogError(exception, "Agent loop failed; continuing after backoff");
                await Task.Delay(TimeSpan.FromSeconds(10), stoppingToken);
            }
        }

        logger.LogInformation("MailShield Agent stopped at {Time}", DateTimeOffset.UtcNow);
    }
}
