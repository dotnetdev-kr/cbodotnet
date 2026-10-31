using System.Collections;
using System.Reflection;
using System.Runtime.CompilerServices;
using System.Runtime.Loader;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.RegularExpressions;
using Microsoft.Build.Framework;
using Microsoft.Build.Logging;

internal static class Program
{
    private static string RuntimeVersion = "";
    private static readonly Regex Url = new(@"(?:https?://|file:/+)[^\s""'<>;]+", RegexOptions.Compiled | RegexOptions.IgnoreCase);
    private static readonly string[] MetadataNames = ["BaseUrl", "PrivateBaseUrl", "DownloadDestination", "DownloadFileName", "ShouldDownload"];
    private static readonly Regex CopyMessage = new(@"^Copying '(?<source>[^']+)' to '(?<destination>[^']+)'$", RegexOptions.Compiled);
    private static readonly Regex DownloadMessage = new(@"^(?:Downloading|Attempting download) '(?<source>[^']+)' to '(?<destination>[^']+)'$", RegexOptions.Compiled);

    private sealed class DownloadTask
    {
        public bool Relevant { get; set; }
        public List<object> Events { get; } = [];
        public HashSet<string> Paths { get; } = new(StringComparer.Ordinal);
    }

    private static int Main(string[] args)
    {
        if (args.Length != 5)
        {
            Console.Error.WriteLine("Usage: LegacyBinlog BINLOG ANALYSIS-SDK-DIRECTORY NEW-OUTPUT-PREFIX HOST-SOURCE-DIRECTORY RUNTIME-VERSION");
            return 2;
        }
        RuntimeVersion = args[4];
        if (!Regex.IsMatch(RuntimeVersion, @"^(5\.0\.17|3\.1\.32|3\.0\.3)$")) return 2;
        var sdkDirectory = Path.GetFullPath(args[1]);
        AssemblyLoadContext.Default.Resolving += (_, name) =>
        {
            var file = Path.Combine(sdkDirectory, name.Name + ".dll");
            return File.Exists(file) ? AssemblyLoadContext.Default.LoadFromAssemblyPath(file) : null;
        };
        return Replay(args);
    }

    [MethodImpl(MethodImplOptions.NoInlining)]
    private static int Replay(string[] args)
    {
        var input = Path.GetFullPath(args[0]);
        var prefix = Path.GetFullPath(args[2]);
        var matchesPath = prefix + ".jsonl";
        var statusPath = prefix + "-status.json";
        var downloadTasksPath = prefix + "-download-tasks.jsonl";
        var hostSource = Path.GetFullPath(args[3]);
        if (!File.Exists(input) || new[] { matchesPath, statusPath, downloadTasksPath }.Any(File.Exists)
            || hostSource != null && !Directory.Exists(hostSource))
        {
            Console.Error.WriteLine("Input and an optional host source directory must exist; all three outputs must be new.");
            return 2;
        }
        Directory.CreateDirectory(Path.GetDirectoryName(prefix)!);
        var started = DateTimeOffset.UtcNow;
        long events = 0, matches = 0, completedDownloadTasks = 0, downloadEvidenceEvents = 0;
        string? failure = null;
        var tasks = new Dictionary<string, string>();
        var seen = new HashSet<string>(StringComparer.Ordinal);
        var downloadTasks = new Dictionary<string, DownloadTask>(StringComparer.Ordinal);
        using var output = new StreamWriter(new FileStream(matchesPath, FileMode.CreateNew, FileAccess.Write, FileShare.Read));
        using var downloads = new StreamWriter(new FileStream(downloadTasksPath, FileMode.CreateNew, FileAccess.Write, FileShare.Read));

        string Context(BuildEventContext? context) => context == null ? "" : $"{context.NodeId}:{context.ProjectContextId}:{context.TargetId}:{context.TaskId}";
        bool Relevant(string value) => value.Contains("aspnetcore", StringComparison.OrdinalIgnoreCase)
            || value.Contains("dotnet-runtime-" + RuntimeVersion, StringComparison.OrdinalIgnoreCase)
            || value.Contains("AspNetCoreSharedFxRootUrl", StringComparison.OrdinalIgnoreCase);
        bool AllowedUri(string value)
        {
            if (!Uri.TryCreate(value, UriKind.Absolute, out var parsed)) return false;
            if (parsed.IsFile) return true;
            return parsed.Scheme is "http" or "https"
                && ((parsed.Host.Equals("ci.dot.net", StringComparison.OrdinalIgnoreCase)
                    || parsed.Host.Equals("dotnetbuilds.azureedge.net", StringComparison.OrdinalIgnoreCase)
                    || parsed.Host.Equals("dotnetbuilds.blob.core.windows.net", StringComparison.OrdinalIgnoreCase))
                    && parsed.AbsolutePath.StartsWith("/public/", StringComparison.OrdinalIgnoreCase)
                || (parsed.Host.Equals("dotnetcli.blob.core.windows.net", StringComparison.OrdinalIgnoreCase)
                    || parsed.Host.Equals("dotnetcli.azureedge.net", StringComparison.OrdinalIgnoreCase))
                    && parsed.AbsolutePath.StartsWith("/dotnet/", StringComparison.OrdinalIgnoreCase));
        }
        object Fingerprint(string recordedPath)
        {
            string? mapped = null;
            if (hostSource != null)
                foreach (var alias in new[] { hostSource.TrimEnd(Path.DirectorySeparatorChar) + "/" })
                    if (recordedPath.StartsWith(alias, StringComparison.Ordinal))
                    {
                        var candidate = Path.GetFullPath(Path.Combine(hostSource, recordedPath[alias.Length..]));
                        if (candidate.StartsWith(hostSource.TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar, StringComparison.Ordinal))
                            mapped = candidate;
                    }
            if (mapped == null) return new { recordedPath, status = "not-mapped", hostPath = (string?)null };
            if (!File.Exists(mapped)) return new { recordedPath, status = "missing-at-replay", hostPath = mapped };
            using var stream = File.OpenRead(mapped);
            var bytes = stream.Length;
            if (bytes > 1024L * 1024 * 1024) throw new InvalidOperationException("Bounded retained-file hash size exceeded.");
            var sha256 = Convert.ToHexString(SHA256.HashData(stream)).ToLowerInvariant();
            return new { recordedPath, status = "hashed-at-replay", hostPath = mapped, bytes, sha256 };
        }
        void DownloadEvidence(BuildEventArgs e, string kind, string? field, string? value, bool? succeeded = null)
        {
            var context = Context(e.BuildEventContext);
            if (!downloadTasks.TryGetValue(context, out var task)) return;
            if (value != null && Relevant(value)) task.Relevant = true;
            if (task.Events.Count >= 256) throw new InvalidOperationException("Bounded per-download task event count exceeded.");
            var copy = value == null ? Match.Empty : CopyMessage.Match(value);
            var download = value == null ? Match.Empty : DownloadMessage.Match(value);
            string? sourceUri = null, destination = null;
            if (copy.Success)
            {
                kind = "local-copy-attempt";
                var sourcePath = copy.Groups["source"].Value;
                sourceUri = "file://" + sourcePath;
                destination = copy.Groups["destination"].Value;
                task.Paths.Add(sourcePath);
                task.Paths.Add(destination);
            }
            else if (download.Success)
            {
                kind = "network-download-attempt";
                sourceUri = download.Groups["source"].Value;
                destination = download.Groups["destination"].Value;
                if (!AllowedUri(sourceUri)) sourceUri = "[non-public URI omitted]";
                task.Paths.Add(destination);
            }
            if (field == "DestinationPath" && value != null && value.StartsWith('/')) task.Paths.Add(value);
            task.Events.Add(new { eventNumber = events, timestamp = e.Timestamp, eventType = e.GetType().Name,
                kind, field, text = value == null ? null : value.Length <= 4096 ? value : value[..4096],
                textTruncated = value?.Length > 4096, sourceUri, destination, succeeded });
            if (succeeded != null)
            {
                if (task.Relevant)
                {
                    if (++completedDownloadTasks > 128 || (downloadEvidenceEvents += task.Events.Count) > 10000)
                        throw new InvalidOperationException("Bounded relevant DownloadFile task evidence count exceeded.");
                    downloads.WriteLine(JsonSerializer.Serialize(new { context, taskName = "DownloadFile", succeeded,
                        events = task.Events, paths = task.Paths.OrderBy(x => x, StringComparer.Ordinal).Select(Fingerprint),
                        interpretation = "Uri parameters are candidates. Copying/Downloading messages record attempts. A successful task may have reused an existing destination when there is no attempt message. File hashes describe files retained at replay time." }));
                    downloads.Flush();
                }
                downloadTasks.Remove(context);
            }
        }
        void Inspect(BuildEventArgs e, string field, string? value)
        {
            if (string.IsNullOrEmpty(value) || !Relevant(value)) return;
            foreach (Match match in Url.Matches(value))
            {
                var uri = match.Value.TrimEnd(')', ',', ']');
                if (!AllowedUri(uri)) continue;
                var key = e.GetType().Name + "|" + field + "|" + uri;
                if (!seen.Add(key)) continue;
                if (++matches > 10000) throw new InvalidOperationException("Bounded match count exceeded; inspect the filter before continuing.");
                var context = Context(e.BuildEventContext);
                tasks.TryGetValue(context, out var taskName);
                output.WriteLine(JsonSerializer.Serialize(new
                {
                    eventNumber = events,
                    timestamp = e.Timestamp,
                    eventType = e.GetType().Name,
                    context,
                    taskName,
                    field,
                    uri,
                    text = value.Length <= 4096 ? value : value[..4096],
                    textTruncated = value.Length > 4096
                }));
                output.Flush();
            }
        }

        try
        {
            var replay = new BinaryLogReplayEventSource { AllowForwardCompatibility = false };
            replay.AnyEventRaised += (_, e) =>
            {
                events++;
                if (events > 10000000) throw new InvalidOperationException("Bounded replay event count exceeded.");
                if (e is TaskStartedEventArgs startedTask)
                {
                    tasks[Context(e.BuildEventContext)] = startedTask.TaskName;
                    if (startedTask.TaskName == "DownloadFile")
                    {
                        if (downloadTasks.Count >= 512) throw new InvalidOperationException("Bounded concurrent download task count exceeded.");
                        downloadTasks[Context(e.BuildEventContext)] = new DownloadTask();
                        DownloadEvidence(e, "task-started", null, null);
                    }
                }
                if (e is TaskFinishedEventArgs finishedTask && finishedTask.TaskName == "DownloadFile")
                    DownloadEvidence(e, "task-finished", null, null, finishedTask.Succeeded);
                if (e is ProjectStartedEventArgs project)
                {
                    if (project.Properties != null)
                        foreach (var property in project.Properties)
                        {
                            if (property is DictionaryEntry entry)
                                Inspect(e, "property:" + entry.Key, entry.Value?.ToString());
                            else if (property is KeyValuePair<string, string> pair)
                                Inspect(e, "property:" + pair.Key, pair.Value);
                            else Inspect(e, "property", property?.ToString());
                        }
                    return;
                }
                if (e is TaskParameterEventArgs parameter)
                {
                    var field = parameter.ItemType ?? "parameter";
                    if (parameter.Items != null)
                        foreach (var item in parameter.Items)
                        {
                            if (item is ITaskItem taskItem)
                            {
                                Inspect(e, field, taskItem.ItemSpec);
                                if (field is "Uri" or "Uris" or "PrivateUri" or "DestinationPath" or "Overwrite")
                                    DownloadEvidence(e, "task-parameter", field, taskItem.ItemSpec);
                                if (Relevant(taskItem.ItemSpec) || field.Contains("Uri", StringComparison.OrdinalIgnoreCase))
                                    foreach (var name in MetadataNames)
                                        Inspect(e, field + "." + name, taskItem.GetMetadata(name));
                            }
                            else
                            {
                                Inspect(e, field, item?.ToString());
                                if (field is "Uri" or "Uris" or "PrivateUri" or "DestinationPath" or "Overwrite")
                                    DownloadEvidence(e, "task-parameter", field, item?.ToString());
                            }
                        }
                    return;
                }
                Inspect(e, "message", e.Message);
                if (e is BuildMessageEventArgs)
                    DownloadEvidence(e, "message", "message", e.Message);
            };
            replay.Replay(input);
        }
        catch (Exception error)
        {
            failure = error.ToString();
        }
        output.Flush();
        downloads.Flush();
        using var inputStream = File.OpenRead(input);
        var inputSha256 = Convert.ToHexString(SHA256.HashData(inputStream)).ToLowerInvariant();
        var status = new
        {
            schemaVersion = 1,
            startedAtUtc = started,
            finishedAtUtc = DateTimeOffset.UtcNow,
            status = failure == null ? "complete" : "failed",
            completedReplay = failure == null,
            input,
            inputSha256,
            matchesPath,
            downloadTasksPath,
            completedDownloadTasks,
            downloadEvidenceEvents,
            unfinishedDownloadTaskCount = downloadTasks.Count,
            hostGeneratedSourceDirectory = hostSource,
            eventsRead = events,
            matchCount = matches,
            failure,
            scope = "Actual recorded events only; file URLs and known public ci.dot.net/dotnetbuilds/dotnetcli URLs mentioning ASP.NET Core or the selected pinned runtime version. The pinned CoreSDK task uses 'Attempting download' for actual network attempts. Separate bounded DownloadFile execution evidence includes start/finish, candidate Uri/PrivateUri parameters, copy/network attempts and optional retained-file hashes. No project evaluation or build targets are executed."
        };
        File.WriteAllText(statusPath, JsonSerializer.Serialize(status, new JsonSerializerOptions { WriteIndented = true }) + "\n");
        Console.WriteLine(JsonSerializer.Serialize(new { status.status, eventsRead = events, matchCount = matches, completedDownloadTasks, matchesPath, downloadTasksPath, statusPath }));
        return failure == null ? 0 : 1;
    }
}
