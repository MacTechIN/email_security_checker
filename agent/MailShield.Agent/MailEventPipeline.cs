namespace MailShield.Agent;

public sealed record MailAttachment(string FileName, long SizeBytes, string? Sha256 = null);

public sealed record MailEvent(
    string Folder,
    long Uid,
    string Subject,
    string Sender,
    string Body,
    IReadOnlyList<MailAttachment> Attachments,
    DateTimeOffset ReceivedAtUtc);

public sealed record MailSecurityIncident(
    string IncidentCode,
    string Folder,
    long Uid,
    string Severity,
    IReadOnlyList<DlpFinding> Findings,
    DateTimeOffset DetectedAtUtc);

public interface IMailEventSource
{
    IAsyncEnumerable<MailEvent> ReadEventsAsync(CancellationToken cancellationToken);
}

public sealed class MailEventPipeline(DlpScanner scanner, ILogger<MailEventPipeline> logger)
{
    public MailSecurityIncident? Evaluate(MailEvent mail, ControlPlaneClient.Policy policy)
    {
        var attachments = mail.Attachments.Select(item => new AttachmentInput(item.FileName, item.SizeBytes, item.Sha256));
        var result = scanner.Scan(mail.Subject, mail.Body, attachments, policy);
        if (!result.IsRisky)
        {
            logger.LogDebug("Mail event {Folder}/{Uid} passed local policy", mail.Folder, mail.Uid);
            return null;
        }

        var severity = result.Findings.Any(item => item.Severity == "critical") ? "critical" : "high";
        var incident = new MailSecurityIncident("MAIL.DLP", mail.Folder, mail.Uid, severity, result.Findings, DateTimeOffset.UtcNow);
        logger.LogWarning("Mail security incident {Folder}/{Uid} severity {Severity}", mail.Folder, mail.Uid, severity);
        return incident;
    }
}
