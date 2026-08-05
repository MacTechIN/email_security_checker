using System.Net.Http.Json;
using System.Reflection;
using Microsoft.Extensions.Logging;

namespace MailShield.Agent;

public sealed class ControlPlaneClient(HttpClient httpClient, ILogger<ControlPlaneClient> logger)
{
    public sealed record Policy(int Version, string Mode, string[] ProtectedExtensions, bool ExternalRecipientWarning, bool PiiDetection);
    public async Task SendHeartbeatAsync(string tenantId, string deviceId, CancellationToken cancellationToken)
    {
        var payload = new { tenantId, deviceId, agentVersion = Assembly.GetExecutingAssembly().GetName().Version?.ToString() ?? "0.0.0", operatingSystem = Environment.OSVersion.VersionString, status = "online", reportedAtUtc = DateTimeOffset.UtcNow };
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

    public async Task<Policy?> FetchPolicyAsync(string tenantId, string deviceId, CancellationToken cancellationToken)
    {
        try
        {
            var response = await httpClient.GetFromJsonAsync<PolicyResponse>($"/api/v1/agents/{tenantId}/{deviceId}/policy", cancellationToken);
            return response is null ? null : new Policy(response.version, response.mode, response.protectedExtensions ?? [], response.externalRecipientWarning, response.piiDetection);
        }
        catch (HttpRequestException exception)
        {
            logger.LogWarning(exception, "Policy service unavailable; retaining last local policy");
            return null;
        }
    }

    private sealed record PolicyResponse(int version, string mode, string[]? protectedExtensions, bool externalRecipientWarning, bool piiDetection);
}
