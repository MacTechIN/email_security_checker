using System.Net.Http.Json;
using System.Reflection;
using Microsoft.Extensions.Logging;

namespace MailShield.Agent;

public sealed class ControlPlaneClient(HttpClient httpClient, ILogger<ControlPlaneClient> logger)
{
    public async Task SendHeartbeatAsync(string deviceId, CancellationToken cancellationToken)
    {
        var payload = new { deviceId, agentVersion = Assembly.GetExecutingAssembly().GetName().Version?.ToString() ?? "0.0.0", operatingSystem = Environment.OSVersion.VersionString, status = "online", reportedAtUtc = DateTimeOffset.UtcNow };
        try
        {
            using var response = await httpClient.PostAsJsonAsync("/api/v1/agent/heartbeat", payload, cancellationToken);
            if (!response.IsSuccessStatusCode) logger.LogWarning("Heartbeat rejected with HTTP {StatusCode}", (int)response.StatusCode);
            else logger.LogDebug("Heartbeat sent for device {DeviceId}", deviceId);
        }
        catch (HttpRequestException exception)
        {
            logger.LogWarning(exception, "Control plane unavailable; local monitoring continues");
        }
    }
}
