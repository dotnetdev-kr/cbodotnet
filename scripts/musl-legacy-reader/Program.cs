using System.Collections;
using System.Runtime.CompilerServices;
using System.Runtime.Loader;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.Build.Framework;
using Microsoft.Build.Logging;

internal static class Program
{
    private sealed class TaskRecord
    {
        public string Name = "";
        public string? Project;
        public string? File;
        public List<object> Events = new List<object>();
    }

    private static readonly HashSet<string> Selected = new HashSet<string>(StringComparer.Ordinal)
    {
        "Csc", "Fsc", "Crossgen", "RunReadyToRunCompiler", "Crossgen2", "Exec", "Copy", "WriteLinesToFile",
        "GenerateBundledVersions", "GenerateRuntimeGraph", "GenerateDepsFile", "GenerateRuntimeConfigurationFiles",
        "GenerateSdkRuntimeIdentifierChain", "CalculateTemplateVersions", "CollatePackageDownloads",
        "UpdateRuntimeConfig", "GenerateDefaultRuntimeFrameworkVersion", "GetDependencyInfo", "ReplaceFileContents",
        "ResolveAssemblyReference"
    };

    private static int Main(string[] args)
    {
        if (args.Length != 3) return 2;
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
        var prefix = Path.GetFullPath(args[2]);
        if (!File.Exists(input) || File.Exists(prefix + "-tasks.jsonl") || File.Exists(prefix + "-status.json")) return 2;
        Directory.CreateDirectory(Path.GetDirectoryName(prefix)!);
        var active = new Dictionary<string, string>();
        var tasks = new Dictionary<string, TaskRecord>();
        var taskNames = new Dictionary<string, long>(StringComparer.Ordinal);
        long count = 0, completed = 0, written = 0;
        bool? buildSucceeded = null;
        string? failure = null;
        string Context(BuildEventContext? context) => context == null ? "" :
            $"{context.NodeId}:{context.ProjectContextId}:{context.TargetId}:{context.TaskId}";
        using var output = new StreamWriter(new FileStream(prefix + "-tasks.jsonl", FileMode.CreateNew));
        void Event(BuildEventArgs e, string kind, string? field = null, string? text = null,
                   Dictionary<string, string>? metadata = null, bool? succeeded = null)
        {
            if (!tasks.TryGetValue(Context(e.BuildEventContext), out var task)) return;
            // The installer RAR task logs tens of thousands of resolution
            // messages. Its only construction output is this metadata cache;
            // preserve that exact parameter and task boundaries. The complete
            // original binlog is retained independently for full replay.
            if (task.Name == "ResolveAssemblyReference" && kind != "task-started" && kind != "task-finished" &&
                !(kind == "task-parameter" && field == "AssemblyInformationCacheOutputPath") &&
                !(kind == "message" && text?.StartsWith("Task Parameter:AssemblyInformationCacheOutputPath=", StringComparison.Ordinal) == true)) return;
            if (text?.Length > 4 * 1024 * 1024 || task.Events.Count >= 250000)
                throw new InvalidOperationException("Task event bound exceeded");
            task.Events.Add(new { eventNumber = count, timestamp = e.Timestamp, kind, field, text,
                metadata = metadata ?? new Dictionary<string, string>(), succeeded });
        }
        try
        {
            var reader = new BinaryLogReplayEventSource();
            reader.GetType().GetProperty("AllowForwardCompatibility")?.SetValue(reader, false);
            reader.AnyEventRaised += (_, e) =>
            {
                if (++count > 15000000) throw new InvalidOperationException("Replay event bound exceeded");
                var key = Context(e.BuildEventContext);
                if (e is BuildFinishedEventArgs build) buildSucceeded = build.Succeeded;
                if (e is TaskStartedEventArgs start)
                {
                    if (key == "" || active.ContainsKey(key) || active.Count >= 10000)
                        throw new InvalidOperationException("Invalid or duplicate task start");
                    active.Add(key, start.TaskName);
                    taskNames[start.TaskName] = taskNames.TryGetValue(start.TaskName, out var prior) ? prior + 1 : 1;
                    if (Selected.Contains(start.TaskName) && (start.TaskName != "ResolveAssemblyReference" ||
                        start.ProjectFile?.EndsWith("/src/redist/redist.csproj", StringComparison.Ordinal) == true))
                    {
                        tasks.Add(key, new TaskRecord { Name = start.TaskName, Project = start.ProjectFile, File = start.TaskFile });
                        Event(e, "task-started");
                    }
                }
                if (e is TaskParameterEventArgs parameter && tasks.ContainsKey(key) && parameter.Items != null)
                {
                    if (tasks[key].Name == "ResolveAssemblyReference" && parameter.ItemType != "AssemblyInformationCacheOutputPath") return;
                    if (parameter.Items.Count > 100000) throw new InvalidOperationException("Parameter item bound exceeded");
                    foreach (var item in parameter.Items)
                    {
                        var value = item is ITaskItem taskItem ? taskItem.ItemSpec : item?.ToString();
                        var metadata = new Dictionary<string, string>(StringComparer.Ordinal);
                        if (item is ITaskItem withMetadata)
                        {
                            var values = withMetadata.CloneCustomMetadata();
                            if (values.Count > 2048) throw new InvalidOperationException("Metadata bound exceeded");
                            foreach (DictionaryEntry pair in values)
                            {
                                var name = pair.Key.ToString()!;
                                var text = pair.Value?.ToString() ?? "";
                                if (name.Length > 1024 || text.Length > 65536)
                                    throw new InvalidOperationException("Metadata text bound exceeded");
                                metadata.Add(name, text);
                            }
                        }
                        Event(e, "task-parameter", parameter.ItemType, value, metadata);
                    }
                }
                if (e is TaskCommandLineEventArgs command) Event(e, "command-line", text: command.CommandLine);
                else if (e is BuildMessageEventArgs) Event(e, "message", text: e.Message);
                if (e is TaskFinishedEventArgs finish)
                {
                    if (!active.TryGetValue(key, out var name) || name != finish.TaskName)
                        throw new InvalidOperationException("Task finish lacks its original start");
                    active.Remove(key);
                    if (tasks.TryGetValue(key, out var task))
                    {
                        Event(e, "task-finished", succeeded: finish.Succeeded);
                        var line = JsonSerializer.Serialize(new { context = key, taskName = task.Name,
                            projectFile = task.Project, taskFile = task.File, succeeded = finish.Succeeded, events = task.Events });
                        written += Encoding.UTF8.GetByteCount(line) + 1;
                        if (++completed > 100000 || written > 512L * 1024 * 1024)
                            throw new InvalidOperationException("Task evidence bound exceeded");
                        output.WriteLine(line);
                        tasks.Remove(key);
                    }
                }
            };
            reader.Replay(input);
        }
        catch (Exception error) { failure = error.ToString(); }
        output.Flush();
        var passed = failure == null && buildSucceeded == true && active.Count == 0 && tasks.Count == 0 && completed > 0;
        File.WriteAllText(prefix + "-status.json", JsonSerializer.Serialize(new
        {
            schemaVersion = 1, completedReplay = failure == null, buildSucceeded,
            unfinishedTasks = active.Count, unfinishedSelectedTasks = tasks.Count,
            observedEvents = count, completedSelectedTasks = completed, failure,
            observedTaskNames = taskNames,
            inputSha256 = Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(input))).ToLowerInvariant()
        }));
        return passed ? 0 : 1;
    }
}
