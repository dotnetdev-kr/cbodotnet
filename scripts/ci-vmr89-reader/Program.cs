using System.Collections;
using System.Runtime.CompilerServices;
using System.Runtime.Loader;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.RegularExpressions;
using Microsoft.Build.Framework;
using Microsoft.Build.Logging;

internal static class Program
{
    private sealed class Download
    {
        public bool Relevant;
        public List<object> Events = [];
    }

    private static int Main(string[] args)
    {
        if (args.Length != 4 && args.Length != 5)
        {
            Console.Error.WriteLine("Usage: Reader BINLOG SDK-DIRECTORY NEW-PREFIX RUNTIME-VERSION [arm64|x64]");
            return 2;
        }
        if (args.Length == 5 && args[4] != "arm64" && args[4] != "x64") return 2;
        var sdk = Path.GetFullPath(args[1]);
        AssemblyLoadContext.Default.Resolving += (_, name) =>
        {
            var path = Path.Combine(sdk, name.Name + ".dll");
            return File.Exists(path) ? AssemblyLoadContext.Default.LoadFromAssemblyPath(path) : null;
        };
        return Replay(args);
    }

    [MethodImpl(MethodImplOptions.NoInlining)]
    private static int Replay(string[] args)
    {
        var input = Path.GetFullPath(args[0]);
        var output = Path.GetFullPath(args[2]) + "-tasks.jsonl";
        var status = Path.GetFullPath(args[2]) + "-status.json";
        if (!File.Exists(input) || File.Exists(output) || File.Exists(status)) return 2;
        Directory.CreateDirectory(Path.GetDirectoryName(output)!);
        var version = args[3];
        var rid = "linux-" + (args.Length == 5 ? args[4] : "arm64");
        var tasks = new Dictionary<string, Download>();
        var attempt = new Regex("^(?<kind>Copying|Downloading) '(?<source>[^']+)' to '(?<destination>[^']+)'$", RegexOptions.Compiled);
        long count = 0, completed = 0;
        bool? buildSucceeded = null;
        string? failure = null;
        using var stream = new StreamWriter(new FileStream(output, FileMode.CreateNew));
        string Context(BuildEventContext? context) => context == null ? "" : $"{context.NodeId}:{context.ProjectContextId}:{context.TargetId}:{context.TaskId}";
        bool Relevant(string value) => value.Contains("-" + version + "-" + rid + ".tar.gz", StringComparison.Ordinal)
            && (value.Contains("dotnet-runtime-", StringComparison.Ordinal) || value.Contains("aspnetcore-runtime-", StringComparison.Ordinal));
        void Event(BuildEventArgs e, string kind, string? field, string? value, bool? succeeded = null)
        {
            var key = Context(e.BuildEventContext);
            if (!tasks.TryGetValue(key, out var task)) return;
            if (value != null && Relevant(value)) task.Relevant = true;
            if (task.Events.Count >= 256) throw new InvalidOperationException("Download event limit exceeded");
            var match = value == null ? Match.Empty : attempt.Match(value);
            string? source = null, destination = null;
            if (match.Success)
            {
                kind = match.Groups["kind"].Value == "Copying" ? "local-copy-attempt" : "network-download-attempt";
                source = match.Groups["source"].Value;
                destination = match.Groups["destination"].Value;
            }
            task.Events.Add(new { eventNumber = count, timestamp = e.Timestamp, kind, field,
                text = value, source, destination, succeeded });
            if (succeeded != null)
            {
                if (task.Relevant)
                {
                    if (++completed > 128) throw new InvalidOperationException("Download task limit exceeded");
                    stream.WriteLine(JsonSerializer.Serialize(new { context = key, taskName = "DownloadFile", succeeded, events = task.Events }));
                    stream.Flush();
                }
                tasks.Remove(key);
            }
        }
        try
        {
            var reader = new BinaryLogReplayEventSource();
            // MSBuild 17.8 has no forward-compatibility switch; newer readers
            // expose it. Neither path may silently skip an unreadable event.
            reader.GetType().GetProperty("AllowForwardCompatibility")?.SetValue(reader, false);
            reader.AnyEventRaised += (_, e) =>
            {
                if (++count > 10000000) throw new InvalidOperationException("Replay event limit exceeded");
                if (e is BuildFinishedEventArgs build) buildSucceeded = build.Succeeded;
                if (e is TaskStartedEventArgs start && start.TaskName == "DownloadFile")
                {
                    if (tasks.Count >= 512) throw new InvalidOperationException("Concurrent download limit exceeded");
                    tasks[Context(e.BuildEventContext)] = new Download();
                    Event(e, "task-started", null, null);
                }
                if (e is TaskParameterEventArgs parameter && tasks.ContainsKey(Context(e.BuildEventContext)) && parameter.Items != null)
                    foreach (var item in parameter.Items)
                    {
                        var value = item is ITaskItem taskItem ? taskItem.ItemSpec : item?.ToString();
                        if (value != null && value.Length > 16384) throw new InvalidOperationException("Parameter text limit exceeded");
                        Event(e, "task-parameter", parameter.ItemType, value);
                    }
                if (e is BuildMessageEventArgs && tasks.ContainsKey(Context(e.BuildEventContext)))
                {
                    if (e.Message?.Length > 16384) throw new InvalidOperationException("Message text limit exceeded");
                    Event(e, "message", null, e.Message);
                }
                if (e is TaskFinishedEventArgs finish && finish.TaskName == "DownloadFile")
                    Event(e, "task-finished", null, null, finish.Succeeded);
            };
            reader.Replay(input);
        }
        catch (Exception error) { failure = error.ToString(); }
        stream.Flush();
        using var archive = File.OpenRead(input);
        var result = new { status = failure == null ? "complete" : "failed", completedReplay = failure == null,
            inputSha256 = Convert.ToHexString(SHA256.HashData(archive)).ToLowerInvariant(), eventsRead = count,
            completedDownloadTasks = completed, unfinishedTasks = tasks.Count, buildSucceeded, failure,
            scope = "Bounded replay of actual completed DownloadFile tasks; candidates alone do not prove consumption." };
        File.WriteAllText(status, JsonSerializer.Serialize(result, new JsonSerializerOptions { WriteIndented = true }) + "\n");
        return failure == null ? 0 : 1;
    }
}
