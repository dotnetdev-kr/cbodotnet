// Replay only recorded DownloadFile executions; no project targets are run.
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
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
    private sealed class TaskRecord
    {
        public string Context { get; set; } = "";
        public long Started { get; set; }
        public long Finished { get; set; }
        public bool Succeeded { get; set; }
        public List<Attempt> Attempts { get; set; } = new List<Attempt>();
    }
    private sealed class Attempt
    {
        public long Event { get; set; }
        public string Kind { get; set; } = "";
        public string Source { get; set; } = "";
        public string Destination { get; set; } = "";
    }
    private static int Main(string[] args)
    {
        if (args.Length != 3) throw new ArgumentException("Expected BINLOG SDK-DIRECTORY NEW-JSON.");
        string directory = Path.GetFullPath(args[1]);
        AssemblyLoadContext.Default.Resolving += (_, name) => {
            string path = Path.Combine(directory, name.Name + ".dll");
            return File.Exists(path) ? AssemblyLoadContext.Default.LoadFromAssemblyPath(path) : null;
        };
        return Replay(args);
    }
    [MethodImpl(MethodImplOptions.NoInlining)]
    private static int Replay(string[] args)
    {
        var pending = new Dictionary<string, TaskRecord>();
        var completed = new List<TaskRecord>();
        long events = 0;
        var copy = new Regex("^Copying '(?<source>[^']+)' to '(?<destination>[^']+)'$", RegexOptions.Compiled);
        var download = new Regex("^Downloading '(?<source>[^']+)' to '(?<destination>[^']+)'$", RegexOptions.Compiled);
        string Context(BuildEventContext c) => c == null ? "" : $"{c.NodeId}:{c.ProjectContextId}:{c.TargetId}:{c.TaskId}";
        var replay = new BinaryLogReplayEventSource();
        replay.AnyEventRaised += (_, e) => {
            events++;
            if (events > 10000000) throw new InvalidOperationException("Replay event limit exceeded.");
            string key = Context(e.BuildEventContext);
            if (e is TaskStartedEventArgs start && start.TaskName == "DownloadFile") {
                if (pending.Count > 512 || pending.ContainsKey(key)) throw new InvalidOperationException("Ambiguous task context.");
                pending.Add(key, new TaskRecord { Context = key, Started = events });
            }
            if (!pending.TryGetValue(key, out TaskRecord task)) return;
            if (e is BuildMessageEventArgs) {
                Match match = copy.Match(e.Message ?? "");
                string kind = "local-copy";
                if (!match.Success) { match = download.Match(e.Message ?? ""); kind = "network-download"; }
                if (match.Success) {
                    if (task.Attempts.Count >= 64) throw new InvalidOperationException("Task attempt limit exceeded.");
                    task.Attempts.Add(new Attempt { Event = events, Kind = kind,
                        Source = match.Groups["source"].Value, Destination = match.Groups["destination"].Value });
                }
            }
            if (e is TaskFinishedEventArgs finish && finish.TaskName == "DownloadFile") {
                task.Finished = events; task.Succeeded = finish.Succeeded;
                completed.Add(task); pending.Remove(key);
                if (completed.Count > 4096) throw new InvalidOperationException("Download task limit exceeded.");
            }
        };
        replay.Replay(args[0]);
        using var stream = File.OpenRead(args[0]);
        using var sha256 = SHA256.Create();
        string hash = Convert.ToHexString(sha256.ComputeHash(stream)).ToLowerInvariant();
        var result = new { schemaVersion = 1, completedReplay = true, eventsRead = events,
            unfinishedDownloadTasks = pending.Count, inputSha256 = hash, tasks = completed,
            scope = "Actual recorded task starts, copy/network attempts and successful/failed finishes. Candidate URLs are not consumption proof." };
        using var output = new FileStream(args[2], FileMode.CreateNew, FileAccess.Write);
        JsonSerializer.Serialize(output, result, new JsonSerializerOptions { WriteIndented = true });
        Console.WriteLine($"Replayed {events} events and {completed.Count} completed DownloadFile tasks.");
        return 0;
    }
}
