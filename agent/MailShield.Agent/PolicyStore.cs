using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace MailShield.Agent;

public sealed class PolicyStore
{
    private readonly string path = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "MailShield", "policy.bin");

    public void Save(ControlPlaneClient.Policy policy)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        var json = JsonSerializer.Serialize(policy);
        var encrypted = ProtectedData.Protect(Encoding.UTF8.GetBytes(json), null, DataProtectionScope.CurrentUser);
        File.WriteAllBytes(path, encrypted);
    }

    public ControlPlaneClient.Policy? Load()
    {
        if (!File.Exists(path)) return null;
        try
        {
            var encrypted = File.ReadAllBytes(path);
            var json = Encoding.UTF8.GetString(ProtectedData.Unprotect(encrypted, null, DataProtectionScope.CurrentUser));
            return JsonSerializer.Deserialize<ControlPlaneClient.Policy>(json);
        }
        catch (CryptographicException) { return null; }
        catch (JsonException) { return null; }
    }
}
