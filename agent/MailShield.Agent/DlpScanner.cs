using System.Text.RegularExpressions;

namespace MailShield.Agent;

public sealed record AttachmentInput(string FileName, long SizeBytes, string? Sha256 = null);
public sealed record DlpFinding(string Code, string Description, string Severity);
public sealed record DlpResult(IReadOnlyList<DlpFinding> Findings)
{
    public bool IsRisky => Findings.Count > 0;
}

public sealed class DlpScanner
{
    private static readonly Regex ResidentId = new(@"\b\d{6}[- ]?[1-4]\d{6}\b", RegexOptions.Compiled);
    private static readonly Regex PaymentOrAccount = new(@"\b(?:\d[ -]?){13,19}\b", RegexOptions.Compiled);
    private static readonly Regex SecretKeyword = new(@"(?i)password|passwd|비밀번호|인증번호|api[_ -]?key|secret", RegexOptions.Compiled);

    public DlpResult Scan(string subject, string body, IEnumerable<AttachmentInput> attachments, ControlPlaneClient.Policy policy)
    {
        var findings = new List<DlpFinding>();
        var text = $"{subject}\n{body}";
        if (policy.PiiDetection && ResidentId.IsMatch(text))
            findings.Add(new("PII.RESIDENT_ID", "고유식별정보 의심 패턴", "high"));
        if (policy.PiiDetection && PaymentOrAccount.IsMatch(text))
            findings.Add(new("PII.FINANCIAL", "카드·계좌번호 의심 패턴", "high"));
        if (policy.PiiDetection && SecretKeyword.IsMatch(text))
            findings.Add(new("SECRET.KEYWORD", "인증정보 키워드", "high"));

        var protectedExtensions = policy.ProtectedExtensions
            .Where(extension => !string.IsNullOrWhiteSpace(extension))
            .Select(extension => extension.StartsWith('.') ? extension : $".{extension}")
            .ToHashSet(StringComparer.OrdinalIgnoreCase);
        foreach (var attachment in attachments)
        {
            var extension = Path.GetExtension(attachment.FileName);
            if (protectedExtensions.Contains(extension))
                findings.Add(new("FILE.PROTECTED_EXTENSION", $"보호 확장자 첨부: {extension}", "high"));
            if (Regex.IsMatch(attachment.FileName, @"\.(pdf|docx?|xlsx?)\.(exe|scr|js|vbs)$", RegexOptions.IgnoreCase))
                findings.Add(new("FILE.DOUBLE_EXTENSION", "이중 확장자 의심 첨부", "critical"));
        }

        return new DlpResult(findings);
    }
}
