namespace MailShield.Agent;

public sealed class AgentOptions
{
    public const string SectionName = "MailShield";

    public string ControlPlaneUrl { get; set; } = "";
    public string ControlPlaneApiKey { get; set; } = "";
    public string DeviceId { get; set; } = "";
    public string TenantId { get; set; } = "";
    public int HeartbeatSeconds { get; set; } = 30;
    public int PolicyRefreshSeconds { get; set; } = 300;
    public string ImapHost { get; set; } = "";
    public int ImapPort { get; set; } = 993;
    public string MailAddress { get; set; } = "";
    public string ImapFolders { get; set; } = "INBOX,Sent";

    public void Validate()
    {
        if (!Uri.TryCreate(ControlPlaneUrl, UriKind.Absolute, out var uri) ||
            uri.Scheme is not ("https" or "http"))
        {
            throw new InvalidOperationException("MailShield:ControlPlaneUrl은 유효한 HTTP(S) URL이어야 합니다.");
        }

        if (string.IsNullOrWhiteSpace(DeviceId) || DeviceId.Length > 128)
            throw new InvalidOperationException("MailShield:DeviceId는 1~128자의 값이어야 합니다.");

        if (!Guid.TryParse(TenantId, out _))
            throw new InvalidOperationException("MailShield:TenantId는 GUID여야 합니다.");

        if (HeartbeatSeconds is < 5 or > 3600)
        {
            throw new InvalidOperationException("MailShield:HeartbeatSeconds는 5~3600초여야 합니다.");
        }

        if (PolicyRefreshSeconds is < 30 or > 86400)
        {
            throw new InvalidOperationException("MailShield:PolicyRefreshSeconds는 30~86400초여야 합니다.");
        }

        if (ImapPort is < 1 or > 65535)
            throw new InvalidOperationException("MailShield:ImapPort는 1~65535여야 합니다.");
    }
}
