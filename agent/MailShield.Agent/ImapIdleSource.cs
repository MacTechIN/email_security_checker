using MailKit;
using MailKit.Net.Imap;
using MailKit.Search;
using MailKit.Security;
using MimeKit;

namespace MailShield.Agent;

public sealed class ImapIdleSource(
    string host,
    int port,
    string username,
    string appPassword,
    string folderName,
    ILogger<ImapIdleSource> logger) : IMailEventSource
{
    public async IAsyncEnumerable<MailEvent> ReadEventsAsync(
        [System.Runtime.CompilerServices.EnumeratorCancellation] CancellationToken cancellationToken)
    {
        var backoff = TimeSpan.FromSeconds(5);
        uint lastUid = 0;

        while (!cancellationToken.IsCancellationRequested)
        {
            using var client = new ImapClient();
            var pendingEvents = new List<MailEvent>();
            try
            {
                await client.ConnectAsync(host, port, SecureSocketOptions.SslOnConnect, cancellationToken);
                await client.AuthenticateAsync(username, appPassword, cancellationToken);
                var folder = await client.GetFolderAsync(folderName, cancellationToken);
                await folder.OpenAsync(FolderAccess.ReadOnly, cancellationToken);
                logger.LogInformation("IMAP IDLE watcher connected to {Folder}", folderName);

                while (!cancellationToken.IsCancellationRequested)
                {
                    using var idleTimeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
                    idleTimeout.CancelAfter(TimeSpan.FromMinutes(14));
                    await client.IdleAsync(idleTimeout.Token, cancellationToken);
                    await client.NoOpAsync(cancellationToken);

                    var uids = await folder.SearchAsync(SearchQuery.All, cancellationToken);
                    foreach (var uid in uids.Where(item => item.Id > lastUid).OrderBy(item => item.Id))
                    {
                        var message = await folder.GetMessageAsync(uid, cancellationToken);
                        lastUid = Math.Max(lastUid, uid.Id);
                        pendingEvents.Add(ToMailEvent(message, folderName, uid.Id));
                    }
                }
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                yield break;
            }
            catch (Exception exception)
            {
                logger.LogWarning(exception, "IMAP watcher {Folder} failed; reconnecting in {Delay}", folderName, backoff);
                await Task.Delay(backoff, cancellationToken);
                backoff = TimeSpan.FromSeconds(Math.Min(backoff.TotalSeconds * 2, 300));
            }
            finally
            {
                if (client.IsConnected)
                    await client.DisconnectAsync(true, CancellationToken.None);
            }

            foreach (var pendingEvent in pendingEvents)
                yield return pendingEvent;
        }
    }

    private static MailEvent ToMailEvent(MimeMessage message, string folder, uint uid)
    {
        var body = message.TextBody ?? message.HtmlBody ?? string.Empty;
        var attachments = message.Attachments
            .OfType<MimePart>()
            .Select(part => new MailAttachment(part.FileName, part.Content.Stream?.Length ?? 0))
            .ToArray();
        return new MailEvent(folder, uid, message.Subject ?? string.Empty, message.From.ToString(), body, attachments, message.Date);
    }
}
