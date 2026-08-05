using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace MailShield.Agent;

public sealed class AgentWorker(ILogger<AgentWorker> logger, ILoggerFactory loggerFactory, AgentOptions options, ControlPlaneClient controlPlaneClient, PolicyStore policyStore, MailEventPipeline pipeline) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        logger.LogInformation("MailShield Agent starting at {Time}", DateTimeOffset.UtcNow);
        var watcherTasks = StartImapWatchers(stoppingToken);

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
        if (watcherTasks.Count > 0)
            await Task.WhenAll(watcherTasks);
    }

    private List<Task> StartImapWatchers(CancellationToken stoppingToken)
    {
        var appPassword = Environment.GetEnvironmentVariable("MAILSHIELD_IMAP_APP_PASSWORD");
        if (string.IsNullOrWhiteSpace(options.ImapHost) || string.IsNullOrWhiteSpace(options.MailAddress) || string.IsNullOrWhiteSpace(appPassword))
        {
            logger.LogInformation("IMAP 감시 설정이 없어 heartbeat 모드로 실행합니다.");
            return [];
        }

        var tasks = new List<Task>();
        foreach (var folder in options.ImapFolders.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            var source = new ImapIdleSource(options.ImapHost, options.ImapPort, options.MailAddress, appPassword, folder, loggerFactory.CreateLogger<ImapIdleSource>());
            tasks.Add(Task.Run(async () =>
            {
                await foreach (var mail in source.ReadEventsAsync(stoppingToken))
                {
                    var policy = policyStore.Load();
                    if (policy is not null)
                        pipeline.Evaluate(mail, policy);
                }
            }, stoppingToken));
        }
        logger.LogInformation("IMAP IDLE 감시 시작: {Folders}", options.ImapFolders);
        return tasks;
    }
}
