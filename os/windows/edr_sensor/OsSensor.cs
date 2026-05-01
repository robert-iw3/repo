/********************************************************************************
 * SYSTEM:          Deep Sensor - Host Behavioral / ETW Telemetry Engine
 * COMPONENT:       DeepVisibilitySensor.cs (Unmanaged ETW Listener)
 * VERSION:         2.1
 * AUTHOR:          Robert Weber
 * * DESCRIPTION:
 * A high-performance, real-time Event Tracing for Windows (ETW) listener compiled
 * natively into the PowerShell runspace.
 ********************************************************************************/

using System;
using System.IO;
using System.Collections.Concurrent;
using System.Threading.Tasks;
using System.Threading;
using System.Runtime.InteropServices;
using System.Collections.Generic;
using System.Text;
using Microsoft.Diagnostics.Tracing;
using Microsoft.Diagnostics.Tracing.Session;
using Microsoft.Diagnostics.Tracing.Parsers;
using Microsoft.Diagnostics.Tracing.Parsers.Kernel;
using System.Linq;

public class DeepVisibilitySensor {
    public static string ToolkitDirectory = "";
    // =====================================================================
    // NATIVE RUST ML ENGINE FFI INTEGRATION
    // =====================================================================
    [DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SetDllDirectory(string lpPathName);

    [DllImport("DeepSensor_ML_v2.1.dll", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
    private static extern IntPtr init_engine();

    [DllImport("DeepSensor_ML_v2.1.dll", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
    private static extern IntPtr evaluate_telemetry(IntPtr engine, string jsonPayload);

    [DllImport("DeepSensor_ML_v2.1.dll", CallingConvention = CallingConvention.Cdecl)]
    private static extern void free_string(IntPtr ptr);

    [DllImport("DeepSensor_ML_v2.1.dll", CallingConvention = CallingConvention.Cdecl)]
    private static extern void teardown_engine(IntPtr engine);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern uint QueryDosDevice(string lpDeviceName, StringBuilder lpTargetPath, uint ucchMax);

    private static Dictionary<string, string> _deviceMap = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
    private static BlockingCollection<string> _mlWorkQueue = new BlockingCollection<string>(new ConcurrentQueue<string>(), 2000);
    private static CancellationTokenSource _mlCancelSource = new CancellationTokenSource();
    private static IntPtr _mlEnginePtr = IntPtr.Zero;
    private static Task _mlConsumerTask;
    public static int GetMlQueueDepth() => _mlWorkQueue.Count;
    public static int GetPowerShellQueueDepth() => EventQueue.Count;

    private static void EnqueueDiag(string msg) {
        string ts = DateTime.UtcNow.ToString("yyyy-MM-dd HH:mm:ss.fff");
        EventQueue.Enqueue($"{{\"Provider\":\"DiagLog\", \"Timestamp\":\"{ts}\", \"Message\":\"{JsonEscape(msg)}\"}}");
    }

    public static long TotalEventsParsed = 0;
    public static long TotalAlertsGenerated = 0;
    public static long TotalMlEvals = 0;

    public class SigmaConditionItem {
        public string Field;
        public MatchType MatchType;
        public bool MatchAll;
        public string[] Values;
    }

    public class SigmaSelectionBlock {
        public string Name;
        public List<SigmaConditionItem> Conditions = new List<SigmaConditionItem>();
    }

    public class SigmaRule {
        public string id;
        public string title;
        public string category;
        public string severity;
        public string tags;
        public string[] PostfixAST; // e.g., ["selection_img", "selection_cli", "AND", "filter", "NOT", "AND"]
        public Dictionary<string, SigmaSelectionBlock> Blocks = new Dictionary<string, SigmaSelectionBlock>(StringComparer.OrdinalIgnoreCase);
    }

    public enum MatchType {
        Contains,
        StartsWith,
        EndsWith,
        Exact
    }

    public static void InitializePathMap() {
        try {
            foreach (var drive in Environment.GetLogicalDrives()) {
                string d = drive.Substring(0, 2); // Extract "C:"
                StringBuilder sb = new StringBuilder(1024);
                if (QueryDosDevice(d, sb, (uint)sb.Capacity) != 0) {
                    _deviceMap[sb.ToString()] = d;
                }
            }
        } catch { }
    }

    public static string ResolveDosPath(string ntPath) {
        if (string.IsNullOrEmpty(ntPath)) return ntPath;
        foreach (var kvp in _deviceMap) {
            if (ntPath.StartsWith(kvp.Key, StringComparison.OrdinalIgnoreCase)) {
                return kvp.Value + ntPath.Substring(kvp.Key.Length);
            }
        }
        return ntPath;
    }

    private static bool EvaluateMatch(string data, string trigger, MatchType matchType) {
        if (string.IsNullOrEmpty(data) || string.IsNullOrEmpty(trigger)) return false;
        return matchType switch {
            MatchType.Contains => data.IndexOf(trigger, StringComparison.OrdinalIgnoreCase) >= 0,
            MatchType.StartsWith => data.StartsWith(trigger, StringComparison.OrdinalIgnoreCase),
            MatchType.EndsWith => data.EndsWith(trigger, StringComparison.OrdinalIgnoreCase),
            MatchType.Exact => data.Equals(trigger, StringComparison.OrdinalIgnoreCase),
            _ => false
        };
    }

    private static bool EvaluateSigmaRule(SigmaRule rule, string cmd, string path, string image, string parentImage, string fullReg) {
        Dictionary<string, bool> blockResults = new Dictionary<string, bool>(StringComparer.OrdinalIgnoreCase);

        foreach (var kvp in rule.Blocks) {
            bool blockMatched = true;
            bool hasMappedField = false;

            foreach (var condition in kvp.Value.Conditions) {
                string targetString = "";
                bool isFieldMapped = false;

                if (condition.Field.IndexOf("ParentImage", StringComparison.OrdinalIgnoreCase) >= 0 || condition.Field.IndexOf("ParentCommandLine", StringComparison.OrdinalIgnoreCase) >= 0) { targetString = parentImage; isFieldMapped = true; }
                else if (condition.Field.IndexOf("ImageLoaded", StringComparison.OrdinalIgnoreCase) >= 0 || condition.Field.IndexOf("Module", StringComparison.OrdinalIgnoreCase) >= 0) { targetString = path; isFieldMapped = true; }
                else if (condition.Field.IndexOf("Image", StringComparison.OrdinalIgnoreCase) >= 0 || condition.Field.IndexOf("OriginalFileName", StringComparison.OrdinalIgnoreCase) >= 0) { targetString = image; isFieldMapped = true; }
                else if (condition.Field.IndexOf("CommandLine", StringComparison.OrdinalIgnoreCase) >= 0 || condition.Field.IndexOf("Details", StringComparison.OrdinalIgnoreCase) >= 0 || condition.Field.IndexOf("DestinationIp", StringComparison.OrdinalIgnoreCase) >= 0) { targetString = cmd; isFieldMapped = true; }
                else if (condition.Field.IndexOf("Registry", StringComparison.OrdinalIgnoreCase) >= 0 || condition.Field.IndexOf("TargetObject", StringComparison.OrdinalIgnoreCase) >= 0) { targetString = fullReg; isFieldMapped = true; }
                else if (condition.Field.IndexOf("TargetFilename", StringComparison.OrdinalIgnoreCase) >= 0 || condition.Field.IndexOf("Target", StringComparison.OrdinalIgnoreCase) >= 0 || condition.Field.IndexOf("FileName", StringComparison.OrdinalIgnoreCase) >= 0 || condition.Field.IndexOf("DestinationPort", StringComparison.OrdinalIgnoreCase) >= 0) { targetString = path; isFieldMapped = true; }
                if (!isFieldMapped) {
                    continue; // Safely bypass unmapped fields (e.g., Hashes)
                }

                hasMappedField = true;
                bool itemMatched = false;

                if (string.IsNullOrEmpty(targetString)) {
                    itemMatched = false; // Telemetry mapped but empty -> FAIL
                }
                else if (condition.MatchAll) {
                    itemMatched = true;
                    foreach (string val in condition.Values) {
                        if (!EvaluateMatch(targetString, val, condition.MatchType)) { itemMatched = false; break; }
                    }
                }
                else {
                    foreach (string val in condition.Values) {
                        if (EvaluateMatch(targetString, val, condition.MatchType)) { itemMatched = true; break; }
                    }
                }

                if (!itemMatched) { blockMatched = false; break; }
            }

            if (!hasMappedField) {
                blockMatched = false;
            }

            blockResults[kvp.Key] = blockMatched;
        }

        // 2. Execute the Boolean AST (Postfix Evaluation)
        bool[] stack = new bool[rule.PostfixAST.Length];
        int head = 0;

        for (int i = 0; i < rule.PostfixAST.Length; i++) {
            string token = rule.PostfixAST[i];

            if (token == "AND") {
                if (head < 2) return false;
                bool a = stack[--head]; bool b = stack[--head];
                stack[head++] = a && b;
            }
            else if (token == "OR") {
                if (head < 2) return false;
                bool a = stack[--head]; bool b = stack[--head];
                stack[head++] = a || b;
            }
            else if (token == "NOT") {
                if (head < 1) return false;
                bool a = stack[--head];
                stack[head++] = !a;
            }
            else {
                stack[head++] = blockResults.TryGetValue(token, out bool val) ? val : false;
            }
        }

        return head == 1 && stack[0];
    }

    public class HighFidelityTTPRule {
        public string category;
        public string signature_name;
        public string severity;
        public string tactic;
        public string technique;
        public string procedure;
        public string actor_process;
        public MatchType match_type;
        public string[] TriggerStrings = Array.Empty<string>();
        public string[] ExclusionStrings = Array.Empty<string>();
        public string[] ExcludePaths = Array.Empty<string>();
        public string[] ExcludeTargets = Array.Empty<string>();
        public string[] ExcludeTargetValues = Array.Empty<string>();
        public string[] ExcludeActorCmds = Array.Empty<string>();
        public string[] ExcludeActors = Array.Empty<string>();
    }

    public struct TtpRuleMatrix {
        public HighFidelityTTPRule[] ProcRules;
        public HighFidelityTTPRule[] FileRules;
        public HighFidelityTTPRule[] RegRules;
        public HighFidelityTTPRule[] ImgRules;
        public HighFidelityTTPRule[] WmiRules;
        public HighFidelityTTPRule[] NetRules;
    }

    private static TtpRuleMatrix _ttpMatrix;

    public class AggregateBucket {
        public int Count;
        public double SumEntropy;
        public double MaxVelocity;
        public DateTime FirstSeen;
        public DateTime LastSeen;
        public HashSet<int> Tids = new();
        public string SampleCmd;
        public string OriginalJson;
        public string SignatureName;
        public string Tactic;
        public string Technique;
        public string Procedure;
        public string Severity;
        public string EventUser;
    }

    public static void SafeEnqueueEvent(string jsonPayload) {
        if (EventQueue == null) return;
        EventQueue.Enqueue(jsonPayload);
    }

    public static void InjectUebaTelemetry(string jsonEvent) {
        if (_mlEnginePtr == IntPtr.Zero || _mlWorkQueue == null) return;
        try {
            if (!_mlWorkQueue.IsAddingCompleted) {
                _mlWorkQueue.Add(jsonEvent);
            }
        } catch (InvalidOperationException) { /* Prevents Orchestrator Fatal Crashes */ }
    }

    public class UebaAggregator {
        private readonly ConcurrentDictionary<string, AggregateBucket> _buckets = new();
        private readonly TimeSpan _window = TimeSpan.FromSeconds(5);

        public UebaAggregator() {
            Task.Run(async () => {
                while (!_mlCancelSource.Token.IsCancellationRequested) {
                    try {
                        await Task.Delay(2000, _mlCancelSource.Token);
                        var now = DateTime.UtcNow;
                        foreach (var kvp in _buckets) {
                            if ((now - kvp.Value.FirstSeen) > _window) {
                                if (_buckets.TryRemove(kvp.Key, out var b)) {
                                    FlushBucket(kvp.Key, b, b.OriginalJson);
                                }
                            }
                        }
                    } catch (OperationCanceledException) { break; }
                }
            }, _mlCancelSource.Token);
        }

        public void AddEvent(string originalJson, string parent, string process, string type, string matchedIndicator, string cmd, string path, int tid, string eventUser, string sigName = "", string tactic = "", string tech = "", string proc = "", string sev = "") {
            if (string.IsNullOrWhiteSpace(originalJson)) return;

            try {
                string key = $"{parent}|{process}|{type}|{matchedIndicator}";

                if (_buckets.Count > 1500) {
                    var oldestKeys = _buckets.OrderBy(kvp => kvp.Value.FirstSeen).Take(300).Select(kvp => kvp.Key).ToList();
                    foreach (var oldKey in oldestKeys) {
                        if (_buckets.TryRemove(oldKey, out var oldBucket))
                            FlushBucket(oldKey, oldBucket, oldBucket.OriginalJson);
                    }
                }

                var bucket = _buckets.GetOrAdd(key, _ => new AggregateBucket {
                    FirstSeen = DateTime.UtcNow,
                    SampleCmd = string.IsNullOrEmpty(cmd) ? path : cmd,
                    OriginalJson = originalJson,
                    SignatureName = sigName,
                    Tactic = tactic,
                    Technique = tech,
                    Procedure = proc,
                    Severity = sev,
                    EventUser = eventUser
                });

                bucket.Count++;
                bucket.SumEntropy += ShannonEntropy(cmd + path);
                bucket.MaxVelocity = Math.Max(bucket.MaxVelocity, CalculateVelocity(cmd));
                bucket.LastSeen = DateTime.UtcNow;
                bucket.Tids.Add(tid);

                if (bucket.Count >= 100) {
                    if (_buckets.TryRemove(key, out var b)) {
                        FlushBucket(key, b, b.OriginalJson);
                    }
                }
            } catch { /* fail open */ }
        }

        private void FlushBucket(string key, AggregateBucket b, string originalJson) {
            double ratePerSec = b.Count / Math.Max(0.1, (b.LastSeen - b.FirstSeen).TotalSeconds);
            double avgEntropy = b.SumEntropy / b.Count;
            string[] parts = key.Split('|');

            string json = $@"{{
                ""Category"":""AggregatedUEBA"",
                ""Type"":""{JsonEscape(parts[2])}"",
                ""Process"":""{JsonEscape(parts[1])}"",
                ""Parent"":""{JsonEscape(parts[0])}"",
                ""Cmd"":""{JsonEscape(b.SampleCmd)}"",
                ""MatchedIndicator"":""{JsonEscape(parts[3])}"",
                ""Count"":{b.Count},
                ""RatePerSec"":{ratePerSec:F2},
                ""AvgEntropy"":{avgEntropy:F2},
                ""MaxVelocity"":{b.MaxVelocity:F2},
                ""UniqueTids"":{b.Tids.Count},
                ""FirstSeen"":""{b.FirstSeen:O}"",
                ""LastSeen"":""{b.LastSeen:O}"",
                ""OriginalSample"":""{JsonEscape(originalJson)}"",
                ""SignatureName"":""{JsonEscape(b.SignatureName)}"",
                ""Tactic"":""{JsonEscape(b.Tactic)}"",
                ""Technique"":""{JsonEscape(b.Technique)}"",
                ""Procedure"":""{JsonEscape(b.Procedure)}"",
                ""Severity"":""{JsonEscape(b.Severity)}"",
                ""ComputerName"":""{HostComputerName}"",
                ""IP"":""{HostIP}"",
                ""OS"":""{HostOS}"",
                ""SensorUser"":""{SensorUser}"",
                ""EventUser"":""{JsonEscape(b.EventUser)}""
            }}".Replace("\r", "").Replace("\n", "").Replace("  ", "");

            if (_mlEnginePtr != IntPtr.Zero && !_mlWorkQueue.IsAddingCompleted)
                _mlWorkQueue.Add(json);
        }
    }

    private static double CalculateVelocity(string cmd) {
        double velocity = 1.0;
        if (!string.IsNullOrEmpty(cmd)) {
            velocity = Math.Min(8.0, cmd.Length / 8.0);

            string cmdLower = cmd.ToLowerInvariant();
            if (cmdLower.Contains("base64") || cmdLower.Contains("-enc") ||
                cmdLower.Contains("frombase64") || cmdLower.Contains("iex") ||
                cmdLower.Contains("invoke-expression")) {
                velocity *= 1.9;
            }
            if (cmdLower.Contains("powershell") && cmdLower.Contains("-nop")) {
                velocity *= 1.4;
            }
        }
        return Math.Min(18.0, velocity);
    }

    public static ConcurrentQueue<string> EventQueue = new ConcurrentQueue<string>();
    private static libyaraNET.YaraContext _yaraContext;
    private static TraceEventSession _session;
    private static Thread _umThread;
    public static bool IsArmed = false;
    private static BlockingCollection<string> _yaraScanQueue = new BlockingCollection<string>();
    private static CancellationTokenSource _yaraCts = new CancellationTokenSource();
    private static readonly object _yaraLock = new object();
    private static ConcurrentDictionary<int, string> ProcessCache = new ConcurrentDictionary<int, string>();
    private static ConcurrentDictionary<int, DateTime> ProcessStartTime = new ConcurrentDictionary<int, DateTime>();
    private static ConcurrentDictionary<int, string> ProcessUserCache = new ConcurrentDictionary<int, string>();
    private static ConcurrentDictionary<int, ModuleMap[]> ProcessModules = new ConcurrentDictionary<int, ModuleMap[]>();
    private static int SensorPid = -1;
    public static string HostComputerName = "";
    public static string HostIP = "";
    public static string HostOS = "";
    public static string SensorUser = "";

    public struct ModuleMap : IComparable<ModuleMap> {
        public string ModuleName;
        public ulong BaseAddress;
        public ulong EndAddress;

        public int CompareTo(ModuleMap other) {
            return BaseAddress.CompareTo(other.BaseAddress);
        }
    }

    public static ConcurrentDictionary<string, byte> BenignLineages = new ConcurrentDictionary<string, byte>(
        new Dictionary<string, byte>(StringComparer.OrdinalIgnoreCase) {
            // Windows Initialization & Core Services
            { "wininit.exe|services.exe", 0 }, { "wininit.exe|lsass.exe", 0 }, { "wininit.exe|lsm.exe", 0 },

            // Service Control Manager Spawns
            { "services.exe|svchost.exe", 0 }, { "services.exe|spoolsv.exe", 0 }, { "services.exe|msmpeng.exe", 0 },
            { "services.exe|searchindexer.exe", 0 }, { "services.exe|officeclicktorun.exe", 0 }, { "services.exe|winmgmt.exe", 0 },

            // Standard Service Host (svchost) Spawns
            { "svchost.exe|taskhostw.exe", 0 }, { "svchost.exe|wmiprvse.exe", 0 }, { "svchost.exe|dllhost.exe", 0 },
            { "svchost.exe|sppsvc.exe", 0 }, { "svchost.exe|searchprotocolhost.exe", 0 }, { "svchost.exe|searchfilterhost.exe", 0 },
            { "svchost.exe|audiodg.exe", 0 }, { "svchost.exe|smartscreen.exe", 0 },

            // Background / Ambient Noise
            { "explorer.exe|onedrive.exe", 0 }, { "taskeng.exe|taskhostw.exe", 0 }
        },
        StringComparer.OrdinalIgnoreCase
    );

    // Uses Immutable Arrays for lock-free, O(1) read operations during StackWalks
    private static void AddOrUpdateModules(int pid, ModuleMap[] modules) {
        Array.Sort(modules);
        if (modules.Length > 150)
        {
            // Trim to top 150 most relevant modules (by address range)
            modules = modules.Take(150).ToArray();
        }
        ProcessModules[pid] = modules;
    }

    public static ConcurrentDictionary<string, byte> SuppressedSigmaRules = new ConcurrentDictionary<string, byte>(StringComparer.OrdinalIgnoreCase);

    public static void SuppressSigmaRule(string ruleName) { SuppressedSigmaRules.TryAdd(ruleName.Trim(), 0); }

    public static ConcurrentDictionary<string, byte> SuppressedProcessRules = new ConcurrentDictionary<string, byte>(StringComparer.OrdinalIgnoreCase);

    public static void SuppressProcessRule(string process, string ruleName) {
        string key = $"{process.Trim()}|{ruleName.Trim()}";
        SuppressedProcessRules.TryAdd(key, 0);
    }

    // CONFIG-DRIVEN SUPPRESSION HELPERS (called from launcher)
    public static void AddBenignLineage(string lineageKey) {
        if (!string.IsNullOrWhiteSpace(lineageKey)) {
            BenignLineages.TryAdd(lineageKey.Trim(), 0);
        }
    }

    public static void SuppressRulesFromConfig(string[] rules) {
        if (rules == null) return;
        foreach (string rule in rules) {
            if (!string.IsNullOrWhiteSpace(rule)) {
                SuppressSigmaRule(rule.Trim());
            }
        }
    }

    public static ConcurrentDictionary<string, libyaraNET.Rules> YaraMatrices = new ConcurrentDictionary<string, libyaraNET.Rules>(StringComparer.OrdinalIgnoreCase);

    public static void InitializeYaraMatrices(string yaraRuleDirectory) {
        if (!System.IO.Directory.Exists(yaraRuleDirectory)) return;

        foreach (var vectorDir in System.IO.Directory.GetDirectories(yaraRuleDirectory)) {
            string vectorName = System.IO.Path.GetFileName(vectorDir);
            try {
                using (var compiler = new libyaraNET.Compiler()) {
                    foreach (var ruleFile in System.IO.Directory.GetFiles(vectorDir, "*.yar")) {
                        compiler.AddRuleFile(ruleFile);
                    }
                    YaraMatrices[vectorName] = compiler.GetRules();
                    EnqueueDiag($"[YARA] Compiled vector matrix: {vectorName}");
                }
            } catch (Exception ex) {
                EnqueueDiag($"[YARA] Failed to compile vector {vectorName}: {ex.Message}");
            }
        }
    }

    public static bool IsYaraRuleValid(string filePath) {
        try {
            using (var compiler = new libyaraNET.Compiler()) {
                compiler.AddRuleFile(filePath);
                return true;
            }
        } catch { return false; }
    }

    public static void InitializeYaraWorker() {
        Task.Run(() => {
            foreach (var filePath in _yaraScanQueue.GetConsumingEnumerable(_yaraCts.Token)) {
                try {
                    Thread.Sleep(500);

                    if (!File.Exists(filePath)) continue;

                    lock (_yaraLock) {
                        if (_yaraContext == null) continue;

                        var scanner = new libyaraNET.Scanner();
                        foreach (var vector in YaraMatrices.Values) {
                            var results = scanner.ScanFile(filePath, vector);
                            if (results != null && results.Count > 0) {
                                foreach (var match in results) {
                                    EnqueueAlert("YARA_Match", "StaticDetection", "Unknown", "Unknown", 0, 0, 0, filePath, $"Rule: {match.MatchingRule.Identifier}", "", match.MatchingRule.Identifier);
                                }
                            }
                        }
                    }
                }
                catch (IOException) { /* File still locked, graceful fail */ }
                catch (Exception ex) { EnqueueDiag($"[YARA WORKER] Scan failed on {filePath}: {ex.Message}"); }
            }
        }, _yaraCts.Token);
    }

    public static string DetermineThreatVector(string processName) {
        // Zero-allocation substring checks instead of processName.ToLowerInvariant().Contains()
        if (processName.IndexOf("w3wp", StringComparison.OrdinalIgnoreCase) >= 0 || processName.IndexOf("nginx", StringComparison.OrdinalIgnoreCase) >= 0 || processName.IndexOf("httpd", StringComparison.OrdinalIgnoreCase) >= 0) return "WebInfrastructure";
        if (processName.IndexOf("spoolsv", StringComparison.OrdinalIgnoreCase) >= 0 || processName.IndexOf("lsass", StringComparison.OrdinalIgnoreCase) >= 0 || processName.IndexOf("smss", StringComparison.OrdinalIgnoreCase) >= 0) return "SystemExploits";
        if (processName.IndexOf("powershell", StringComparison.OrdinalIgnoreCase) >= 0 || processName.IndexOf("cmd", StringComparison.OrdinalIgnoreCase) >= 0 || processName.IndexOf("wscript", StringComparison.OrdinalIgnoreCase) >= 0) return "LotL";
        if (processName.IndexOf("winword", StringComparison.OrdinalIgnoreCase) >= 0 || processName.IndexOf("excel", StringComparison.OrdinalIgnoreCase) >= 0) return "MacroPayloads";
        if (processName.IndexOf("rundll32", StringComparison.OrdinalIgnoreCase) >= 0 || processName.IndexOf("regsvr32", StringComparison.OrdinalIgnoreCase) >= 0) return "BinaryProxy";
        if (processName.IndexOf("explorer", StringComparison.OrdinalIgnoreCase) >= 0 || processName.IndexOf("winlogon", StringComparison.OrdinalIgnoreCase) >= 0) return "SystemPersistence";
        return "Core_C2";
    }

    public static string EvaluatePayloadInMemory(byte[] payload, string processName) {
        string vector = DetermineThreatVector(processName);
        if (!YaraMatrices.ContainsKey(vector)) vector = "Core_C2";
        if (!YaraMatrices.ContainsKey(vector)) return "NoSignatureMatch";

        try {
            // The GC handles the unmanaged teardown natively for the Scanner object in this wrapper.
            var scanner = new libyaraNET.Scanner();
            var results = scanner.ScanMemory(payload, YaraMatrices[vector]);

            if (results != null && results.Count > 0) {
                List<string> matches = new List<string>();
                foreach (var match in results) { matches.Add(match.MatchingRule.Identifier); }
                return string.Join(" | ", matches);
            }
        } catch (Exception ex) { return $"YaraEvaluationError: {ex.Message}"; }
        return "NoSignatureMatch";
    }

    private static bool IsForgedReturnAddress(int pid, ulong returnAddr) {
        if (returnAddr < 10) return true;
        uint PROCESS_VM_READ_OPERATION = 0x0010 | 0x0008;
        IntPtr hProcess = OpenProcess(PROCESS_VM_READ_OPERATION, false, (uint)pid);
        if (hProcess == IntPtr.Zero) return true;

        try {
            byte[] buffer = new byte[10];
            ulong readAddr = returnAddr - 10;
            if (!ReadProcessMemory(hProcess, (IntPtr)readAddr, buffer, (UIntPtr)10, out _)) return true;

            for (int i = 0; i < 6; i++) {
                byte b = buffer[i];
                if (b == 0xE8 || b == 0xE9 || b == 0xEB) return false;
                if (b == 0xFF) {
                    byte modrm = buffer[i + 1];
                    if ((modrm & 0xF8) == 0xD0 || (modrm & 0xF8) == 0x10 ||
                        (modrm & 0xF8) == 0x50 || (modrm & 0xF8) == 0x90) return false;
                }
            }
            return true;
        } catch { return true; } finally { CloseHandle(hProcess); }
    }

    // EXHAUSTIVE ANTI-BSOD LIST: Touching these will cause system instability or immediate bugchecks
    private static readonly HashSet<string> CriticalSystemProcesses = new HashSet<string>(StringComparer.OrdinalIgnoreCase) {
        "smss.exe", "csrss.exe", "wininit.exe", "services.exe",
        "lsass.exe", "winlogon.exe", "svchost.exe", "lsm.exe",
        "spoolsv.exe", "explorer.exe", "taskhostw.exe", "System"
    };

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern IntPtr OpenThread(uint dwDesiredAccess, bool bInheritHandle, uint dwThreadId);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern uint SuspendThread(IntPtr hThread);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool CloseHandle(IntPtr hObject);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, uint dwProcessId);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool VirtualProtectEx(IntPtr hProcess, IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, UIntPtr nSize, out UIntPtr lpNumberOfBytesRead);

    [DllImport("dbghelp.dll", SetLastError = true)]
    static extern bool MiniDumpWriteDump(IntPtr hProcess, uint processId, Microsoft.Win32.SafeHandles.SafeFileHandle hFile, uint dumpType, IntPtr expParam, IntPtr userStreamParam, IntPtr callbackParam);

    // =====================================================================
    // SENSOR SELF-DEFENSE (SAFE MEMORY HARDENING)
    // =====================================================================
    public static class SensorSelfDefense {
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool SetProcessMitigationPolicy(int policy, ref long lpBuffer, int size);

        public static void LockProcessMemory() {
            try {
                // Memory Injection Protection (ImageLoadPolicy)
                // Prevents attackers from injecting unsigned DLLs from UNC paths (SMB)
                // or low-integrity directories (like %TEMP%). This prevents internal blinding.
                // Policy: ProcessImageLoadPolicy (10)
                // Flags: NoRemoteImages (1) | NoLowMandatoryLabelImages (2) = 3
                long imgPolicy = 3;
                SetProcessMitigationPolicy(10, ref imgPolicy, sizeof(long));

            } catch {
                // Fail open if privileges are insufficient
            }
        }
    }

    public static bool QuarantineNativeThread(int tid, int pid) {
        if (!IsArmed) return false;
        string procName = GetProcessName(pid);
        if (CriticalSystemProcesses.Contains(procName)) return false;

        uint THREAD_SUSPEND_RESUME = 0x0002;
        IntPtr hThread = OpenThread(THREAD_SUSPEND_RESUME, false, (uint)tid);
        if (hThread == IntPtr.Zero) return false;

        uint suspendCount = SuspendThread(hThread);
        CloseHandle(hThread);
        return (suspendCount != 0xFFFFFFFF);
    }

    public static string NeuterAndDumpPayload(int pid, ulong address, ulong size) {
        string yaraResult = "NoSignatureMatch";
        string procName = GetProcessName(pid);
        if (CriticalSystemProcesses.Contains(procName)) return yaraResult;

        // Prevent malware from crashing the EDR via massive RWX heap sprays (Cap at 50MB)
        if (size > 52428800) return "AllocationExceedsScanLimit";

        uint PROCESS_VM_READ_OPERATION = 0x0010 | 0x0008;
        IntPtr hProcess = OpenProcess(PROCESS_VM_READ_OPERATION, false, (uint)pid);
        if (hProcess == IntPtr.Zero) return "HandleAccessDenied";

        try {
            byte[] buffer = new byte[size];
            if (ReadProcessMemory(hProcess, (IntPtr)address, buffer, (UIntPtr)size, out UIntPtr bytesRead)) {
                yaraResult = EvaluatePayloadInMemory(buffer, procName);

                // Only write to disk if it actually matches a YARA rule to save I/O overhead
                if (yaraResult != "NoSignatureMatch") {
                    string quarantineDir = @"C:\ProgramData\DeepSensor\Data\Quarantine";
                    System.IO.Directory.CreateDirectory(quarantineDir);
                    string dumpPath = $@"{quarantineDir}\Payload_{procName}_{pid}_0x{address:X}.bin";
                    System.IO.File.WriteAllBytes(dumpPath, buffer);
                }
            }

            uint PAGE_NOACCESS = 0x01;
            VirtualProtectEx(hProcess, (IntPtr)address, (UIntPtr)size, PAGE_NOACCESS, out uint oldProtect);
        } catch { return "ForensicError"; } finally { CloseHandle(hProcess); }
        return yaraResult;
    }

    public static string PreserveForensics(int pid, string procName) {
        if (!IsArmed) return "Bypassed";
        string dumpDir = @"C:\ProgramData\DeepSensor\Data\Forensics";
        System.IO.Directory.CreateDirectory(dumpDir);
        string dumpPath = $@"{dumpDir}\{procName}_{pid}_{DateTime.UtcNow:yyyyMMddHHmmss}.dmp";

        IntPtr hProcess = OpenProcess(0x0400 | 0x0010, false, (uint)pid);
        if (hProcess == IntPtr.Zero) return "AccessDenied";

        try {
            using (var fs = new System.IO.FileStream(dumpPath, System.IO.FileMode.Create, System.IO.FileAccess.ReadWrite, System.IO.FileShare.Write)) {
                if (MiniDumpWriteDump(hProcess, (uint)pid, fs.SafeFileHandle, 2, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero)) {
                    return dumpPath;
                }
            }
        } catch { } finally { CloseHandle(hProcess); }
        return "Failed";
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern uint ResumeThread(IntPtr hThread);

    // ROLLBACK MECHANISM
    public static bool ResumeNativeThread(int tid) {
        uint THREAD_SUSPEND_RESUME = 0x0002;
        IntPtr hThread = OpenThread(THREAD_SUSPEND_RESUME, false, (uint)tid);
        if (hThread == IntPtr.Zero) return false;
        uint resumeCount = ResumeThread(hThread);
        CloseHandle(hThread);

        // If resumeCount is > 0, it successfully decremented the suspension count
        return (resumeCount != 0xFFFFFFFF);
    }

    private static readonly string[] MonitoredRegPaths = {
        "image file execution options", "inprocserver32", "treatas",
        "windows\\currentversion\\run", "session manager", "services",
        "wmi\\autologger", "amsi\\providers", "control\\lsa\\security packages"
    };

    private static double ShannonEntropy(string s) {
        if (string.IsNullOrEmpty(s)) return 0.0;
        var counts = new Dictionary<char, int>();
        foreach (char c in s) { counts[c] = counts.GetValueOrDefault(c) + 1; }
        double entropy = 0.0;
        int len = s.Length;
        foreach (var count in counts.Values) {
            double p = (double)count / len;
            entropy -= p * Math.Log(p, 2);
        }
        return entropy;
    }

    private static HashSet<string> BenignExplorerValueNames = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
    private static HashSet<string> BenignADSProcesses       = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
    private static HashSet<string> TiDrivers = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

    public class RuleMatrix {
        public SigmaRule[] ProcRules = Array.Empty<SigmaRule>();
        public SigmaRule[] ImgRules  = Array.Empty<SigmaRule>();
        public SigmaRule[] FileRules = Array.Empty<SigmaRule>();
        public SigmaRule[] RegRules  = Array.Empty<SigmaRule>();
        public SigmaRule[] WmiRules  = Array.Empty<SigmaRule>();
        public SigmaRule[] NetRules  = Array.Empty<SigmaRule>();
    }

    private static RuleMatrix _activeMatrix = new RuleMatrix();

    public static void UpdateSigmaRules(string b64Rules) {
        try {
            var matrix = new RuleMatrix();
            if (string.IsNullOrEmpty(b64Rules)) return;

            string payload = System.Text.Encoding.UTF8.GetString(Convert.FromBase64String(b64Rules));
            string[] rules = payload.Split(new string[] { "[NEXT]" }, StringSplitOptions.RemoveEmptyEntries);

            var procList = new List<SigmaRule>();
            var imgList = new List<SigmaRule>();
            var fileList = new List<SigmaRule>();
            var regList = new List<SigmaRule>();
            var wmiList = new List<SigmaRule>();
            var netList = new List<SigmaRule>();

            foreach (string r in rules) {
                string[] parts = r.Split('|');
                if (parts.Length < 7) continue;

                var rule = new SigmaRule {
                    category = parts[0],
                    title = parts[1],
                    id = parts[2],
                    severity = parts[3],
                    tags = parts[4],
                    PostfixAST = parts[5].Split(',')
                };

                string[] blocks = parts[6].Split('~');
                foreach (string block in blocks) {
                    if (string.IsNullOrEmpty(block)) continue;
                    string[] bParts = block.Split('>');
                    if (bParts.Length < 2) continue;

                    string blockName = bParts[0];
                    var selection = new SigmaSelectionBlock { Name = blockName };
                    string[] fields = bParts[1].Split('^');

                    foreach (string field in fields) {
                        string[] fParts = field.Split(new char[] { ':' }, 4);
                        if (fParts.Length < 4) continue;

                        selection.Conditions.Add(new SigmaConditionItem {
                            Field = fParts[0],
                            MatchType = (MatchType)Enum.Parse(typeof(MatchType), fParts[1], true),
                            MatchAll = fParts[2] == "true",
                            Values = fParts[3].Split('\t')
                        });
                    }
                    rule.Blocks[blockName] = selection;
                }

                switch (rule.category.ToLowerInvariant()) {
                    case "process_creation": procList.Add(rule); break;
                    case "image_load": imgList.Add(rule); break;
                    case "file_event": fileList.Add(rule); break;
                    case "registry_event":
                    case "registry_set": regList.Add(rule); break;
                    case "wmi_event": wmiList.Add(rule); break;
                    case "network_connection": netList.Add(rule); break;
                }
            }

            matrix.ProcRules = procList.ToArray();
            matrix.ImgRules = imgList.ToArray();
            matrix.FileRules = fileList.ToArray();
            matrix.RegRules = regList.ToArray();
            matrix.WmiRules = wmiList.ToArray();
            matrix.NetRules = netList.ToArray();

            Interlocked.Exchange(ref _activeMatrix, matrix);
        } catch (Exception ex) {
            EnqueueDiag($"[OS SENSOR] AST Compilation Failed - {ex.Message}");
        }
    }

    public static void UpdateTtpRules(string base64Payload) {
        if (string.IsNullOrWhiteSpace(base64Payload)) return;

        var procList = new List<HighFidelityTTPRule>();
        var fileList = new List<HighFidelityTTPRule>();
        var regList = new List<HighFidelityTTPRule>();
        var imgList = new List<HighFidelityTTPRule>();
        var wmiList = new List<HighFidelityTTPRule>();

        try {
            string payload = Encoding.UTF8.GetString(Convert.FromBase64String(base64Payload));
            string[] rules = payload.Split(new[] { "[NEXT]" }, StringSplitOptions.RemoveEmptyEntries);

            foreach (string r in rules) {
                string[] parts = r.Split('|');
                if (parts.Length < 10) continue;

                var rule = new HighFidelityTTPRule {
                    category = parts[0],
                    signature_name = parts[1],
                    severity = parts[2],
                    tactic = parts[3],
                    technique = parts[4],
                    procedure = parts[5],
                    actor_process = parts[6].ToLowerInvariant(),
                    match_type = (MatchType)Enum.Parse(typeof(MatchType), parts[7], true),
                };

                string triggerDecoded = Encoding.UTF8.GetString(Convert.FromBase64String(parts[8])).ToLowerInvariant();
                rule.TriggerStrings = triggerDecoded.Split(new[] { ',' }, StringSplitOptions.RemoveEmptyEntries)
                    .Select(s => s.Trim()).Where(s => !string.IsNullOrWhiteSpace(s)).ToArray();

                string exclusionDecoded = (parts.Length > 9 && !string.IsNullOrWhiteSpace(parts[9]))
                    ? Encoding.UTF8.GetString(Convert.FromBase64String(parts[9])).ToLowerInvariant() : "";
                rule.ExclusionStrings = exclusionDecoded.Split(new[] { ',' }, StringSplitOptions.RemoveEmptyEntries)
                    .Select(s => s.Trim()).Where(s => !string.IsNullOrWhiteSpace(s)).ToArray();

                string epDecoded = (parts.Length > 10 && !string.IsNullOrWhiteSpace(parts[10]))
                    ? Encoding.UTF8.GetString(Convert.FromBase64String(parts[10])).ToLowerInvariant() : "";
                rule.ExcludePaths = epDecoded.Split(new[] { ',' }, StringSplitOptions.RemoveEmptyEntries)
                    .Select(s => s.Trim()).Where(s => !string.IsNullOrWhiteSpace(s)).ToArray();

                string etDecoded = (parts.Length > 11 && !string.IsNullOrWhiteSpace(parts[11]))
                    ? Encoding.UTF8.GetString(Convert.FromBase64String(parts[11])).ToLowerInvariant() : "";
                rule.ExcludeTargets = etDecoded.Split(new[] { ',' }, StringSplitOptions.RemoveEmptyEntries)
                    .Select(s => s.Trim()).Where(s => !string.IsNullOrWhiteSpace(s)).ToArray();

                string etvDecoded = (parts.Length > 12 && !string.IsNullOrWhiteSpace(parts[12]))
                    ? Encoding.UTF8.GetString(Convert.FromBase64String(parts[12])).ToLowerInvariant() : "";
                rule.ExcludeTargetValues = etvDecoded.Split(new[] { ',' }, StringSplitOptions.RemoveEmptyEntries)
                    .Select(s => s.Trim()).Where(s => !string.IsNullOrWhiteSpace(s)).ToArray();

                string eacDecoded = (parts.Length > 13 && !string.IsNullOrWhiteSpace(parts[13]))
                    ? Encoding.UTF8.GetString(Convert.FromBase64String(parts[13])).ToLowerInvariant() : "";
                rule.ExcludeActorCmds = eacDecoded.Split(new[] { ',' }, StringSplitOptions.RemoveEmptyEntries)
                    .Select(s => s.Trim()).Where(s => !string.IsNullOrWhiteSpace(s)).ToArray();

                string eaDecoded = (parts.Length > 14 && !string.IsNullOrWhiteSpace(parts[14]))
                    ? Encoding.UTF8.GetString(Convert.FromBase64String(parts[14])).ToLowerInvariant() : "";
                rule.ExcludeActors = eaDecoded.Split(new[] { ',' }, StringSplitOptions.RemoveEmptyEntries)
                    .Select(s => s.Trim()).Where(s => !string.IsNullOrWhiteSpace(s)).ToArray();

                switch (rule.category.ToLowerInvariant()) {
                    case "process_creation": procList.Add(rule); break;
                    case "image_load": imgList.Add(rule); break;
                    case "file_event": fileList.Add(rule); break;
                    case "registry_event":
                    case "registry_set": regList.Add(rule); break;
                    case "wmi_event": wmiList.Add(rule); break;
                }
            }

            _ttpMatrix = new TtpRuleMatrix {
                ProcRules = procList.ToArray(),
                FileRules = fileList.ToArray(),
                RegRules = regList.ToArray(),
                ImgRules = imgList.ToArray(),
                WmiRules = wmiList.ToArray()
            };
        } catch { /* Fail silently to protect the sensor */ }
    }

    [ThreadStatic]
    private static StringBuilder _jsonSb;

    private static string JsonEscape(string text) {
        if (string.IsNullOrEmpty(text)) return "";
        if (_jsonSb == null) _jsonSb = new StringBuilder(text.Length * 2);
        _jsonSb.Clear();

        foreach (char c in text) {
            switch (c) {
                case '"':  _jsonSb.Append("\\\""); break;
                case '\\': _jsonSb.Append("\\\\"); break;
                case '\b': _jsonSb.Append("\\b"); break;
                case '\f': _jsonSb.Append("\\f"); break;
                case '\n': _jsonSb.Append("\\n"); break;
                case '\r': _jsonSb.Append("\\r"); break;
                case '\t': _jsonSb.Append("\\t"); break;
                default:
                    if (c < ' ') _jsonSb.AppendFormat("\\u{0:x4}", (int)c);
                    else _jsonSb.Append(c);
                    break;
            }
        }
        return _jsonSb.ToString();
    }

    private static UebaAggregator _aggregator = new UebaAggregator();

    private static string BuildEnrichedJson(
        string category, string eventType, string process, string parentProcess,
        int pid, int parentPid, int tid, string cmdline, string details,
        string path = "", string extraType = "", string matchedIndicator = "",
        string signatureName = "", string severity = "", string tags = "",
        string destinationIp = "", int destPort = 0)
    {

        string procLower = process.ToLowerInvariant();
        string parentLower = parentProcess.ToLowerInvariant();
        string eventUser = GetEventUser(pid);

        string lineageKey = $"{parentProcess}|{process}";
        if (BenignLineages.ContainsKey(lineageKey)) return null;

        if (BenignADSProcesses.Contains(procLower) || BenignADSProcesses.Contains(parentLower)) return null;

        string json = $@"{{
            ""Category"":""{category}"",
            ""Type"":""{eventType}"",
            ""Process"":""{JsonEscape(process)}"",
            ""Parent"":""{JsonEscape(parentProcess)}"",
            ""PID"":{pid},
            ""ParentPID"":{parentPid},
            ""TID"":{tid},
            ""Cmd"":""{JsonEscape(cmdline)}"",
            ""Details"":""{JsonEscape(details)}"",
            ""Path"":""{JsonEscape(path)}"",
            ""ComputerName"":""{HostComputerName}"",
            ""IP"":""{JsonEscape(HostIP)}"",
            ""OS"":""{HostOS}"",
            ""SensorUser"":""{SensorUser}"",
            ""EventUser"":""{JsonEscape(eventUser)}"",
            ""Destination"":""{JsonEscape(destinationIp)}"",
            ""Port"":{destPort},
            ""MatchedIndicator"":""{JsonEscape(matchedIndicator)}"",
            ""SignatureName"":""{JsonEscape(signatureName)}"",
            ""Severity"":""{JsonEscape(severity)}"",
            ""ATTCKMappings"":""{JsonEscape(tags)}""
        }}".Replace("\r", "").Replace("\n", "").Replace("  ", "");

        return json;
    }

    public static void SetLibraryPath(string path) { SetDllDirectory(path); }

    private static string _dllPath;

    public static void Initialize(string dllPath, int currentPid, string[] tiDrivers, string[] benignExplorerValues, string[] benignADSProcs) {
        _dllPath = dllPath;
        SensorPid = currentPid;
        HostComputerName = JsonEscape(Environment.MachineName);
        HostOS           = JsonEscape("Windows");
        SensorUser       = JsonEscape(Environment.UserDomainName + "\\" + Environment.UserName);

        try {
            _yaraContext = new libyaraNET.YaraContext();
            EnqueueDiag("[YARA] Native context initialized successfully.");
        } catch (Exception ex) { EnqueueDiag($"[YARA] Context Init Failed: {ex.Message}"); }

        // --- NATIVE RUST ENGINE FFI IMPORT ---
        try {
            _mlEnginePtr = init_engine();
            if (_mlEnginePtr != IntPtr.Zero) {
                // Success: Engine is mapped and database is ready
                EnqueueDiag("[ML ENGINE] Native DLL successfully mapped at memory address: 0x" + _mlEnginePtr.ToString("X"));
                EnqueueDiag("[ML ENGINE] UEBA Database initialized at C:\\ProgramData\\DeepSensor\\Data\\DeepSensor_UEBA.db");
            } else {
                // Failure: Pointer is null. Likely causes: DB locked or missing DLL.
                EnqueueDiag("[ML ENGINE ERROR] init_engine returned NULL. Database may be locked or path inaccessible.");
            }
        } catch (Exception ex) {
            // Failure: Critical FFI crash (e.g., mismatched architecture or missing entry point)
            EnqueueDiag($"[ML ENGINE ERROR] FFI Import Failed: {ex.Message}");
        }

        foreach (var p in System.Diagnostics.Process.GetProcesses()) {
            try { ProcessCache[p.Id] = p.ProcessName + ".exe"; } catch { }
        }

        BenignExplorerValueNames = new HashSet<string>(benignExplorerValues, StringComparer.OrdinalIgnoreCase);
        BenignADSProcesses       = new HashSet<string>(benignADSProcs,       StringComparer.OrdinalIgnoreCase);

        // SENSOR HYGIENE & MEMORY MAINTENANCE LOOP
        Task.Run(async () => {
            while (!_mlCancelSource.Token.IsCancellationRequested) {
                try {
                    await Task.Delay(300_000, _mlCancelSource.Token);

                    var cutoff = DateTime.UtcNow.AddHours(-24);
                    var keysToRemove = new List<int>();

                    var items = ProcessStartTime.ToArray();
                    foreach (var kvp in items) {
                        if (kvp.Value < cutoff) keysToRemove.Add(kvp.Key);
                    }

                    // Memory Protection: Cap the metadata cache to 10,000 entries
                    int remaining = items.Length - keysToRemove.Count;
                    if (remaining > 10000) {
                        var oldestToPrune = items.Where(x => !keysToRemove.Contains(x.Key))
                                                 .OrderBy(x => x.Value)
                                                 .Take(remaining - 8000);
                        foreach(var o in oldestToPrune) keysToRemove.Add(o.Key);
                    }

                    // Rule Fatigue Protection: Cap suppression lists to prevent exhaustion
                    if (SuppressedProcessRules.Count > 10000) {
                        SuppressedProcessRules.Clear();
                        EnqueueDiag("[MAINTENANCE] Flushed SuppressedProcessRules cache to prevent RAM exhaustion.");
                    }

                    // Finalize the purge of stale PIDs
                    foreach (var pid in keysToRemove) {
                        ProcessCache.TryRemove(pid, out _);
                        ProcessStartTime.TryRemove(pid, out _);
                        ProcessModules.TryRemove(pid, out _);
                        ProcessUserCache.TryRemove(pid, out _);
                    }
                }
                // Handle the signal to exit immediately
                catch (OperationCanceledException) {
                    break;
                }
                catch (Exception) {
                    /* Never crash the sensor on hygiene errors */
                }
            }
        }, _mlCancelSource.Token);

        AppDomain.CurrentDomain.AssemblyResolve += (sender, args) => {
            string folderPath = System.IO.Path.GetDirectoryName(_dllPath);
            string assemblyName = new System.Reflection.AssemblyName(args.Name).Name;
            string targetPath = System.IO.Path.Combine(folderPath, assemblyName + ".dll");
            if (System.IO.File.Exists(targetPath)) return System.Reflection.Assembly.LoadFrom(targetPath);
            return null;
        };

        InitializePathMap();
        UpdateThreatIntel(tiDrivers);

        // Start the dedicated ML consumer thread with Micro-Batching
        _mlConsumerTask = Task.Factory.StartNew(() => {
            try {
                while (!_mlWorkQueue.IsCompleted) {
                    var batch = new List<string>();

                    // Block indefinitely until at least ONE event arrives
                    if (_mlWorkQueue.TryTake(out string firstEvent, Timeout.Infinite, _mlCancelSource.Token)) {
                        batch.Add(firstEvent);

                        // Quickly drain up to 999 more events if they are waiting (10ms timeout)
                        while (batch.Count < 1000 && _mlWorkQueue.TryTake(out string nextEvent, 10)) {
                            batch.Add(nextEvent);
                        }

                        if (_mlEnginePtr == IntPtr.Zero) continue;

                        // Wrap the batch in a JSON array format for Rust
                        string jsonArray = "[" + string.Join(",", batch) + "]";
                        Interlocked.Add(ref TotalMlEvals, batch.Count);

                        IntPtr resultPtr = evaluate_telemetry(_mlEnginePtr, jsonArray);
                        if (resultPtr != IntPtr.Zero) {
                            string alertJson = Marshal.PtrToStringAnsi(resultPtr);
                            free_string(resultPtr);
                            if (!string.IsNullOrEmpty(alertJson)) {
                                EventQueue.Enqueue($"[ML_ALERTS]{alertJson}");
                            }
                        }
                    }
                }
            } catch (OperationCanceledException) {
                // Normal shutdown via CancellationToken
            } catch (Exception ex) {
                EnqueueDiag($"[ML CONSUMER FATAL] {ex.Message}");
            }
        }, _mlCancelSource.Token, TaskCreationOptions.LongRunning, TaskScheduler.Default);
    }

    public static void UpdateThreatIntel(string[] tiDrivers) {
        var newTi = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (string driver in tiDrivers) { newTi.Add(driver); }
        TiDrivers = newTi;
    }

    // APPLICATION DIAGNOSTIC PARSERS
    private static void ParsePowerShellScriptBlock(TraceEvent data) {
        try {
            // Extract the raw script block text from the ETW payload
            string scriptPayload = data.PayloadByName("ScriptBlockText") as string ?? string.Empty;

            if (!string.IsNullOrWhiteSpace(scriptPayload)) {
                // Enqueue it to the ML engine as a distinct "ScriptBlock" behavioral event.
                // We bind it to powershell.exe and the specific PID/TID that executed it.
                EnqueueRaw("ScriptBlock", "powershell.exe", "", "", scriptPayload, data.ProcessID, data.ThreadID);
            }
        } catch {
            // Fail open: Never crash the sensor if a diagnostic payload is malformed
        }
    }

    public static void StartSession() {
        Task.Run(() => {
            try { RunEtwCore(); }
            catch (Exception ex) { EventQueue.Enqueue($"{{\"Provider\":\"Error\", \"Message\":\"{JsonEscape(ex.Message)}\"}}"); }
        });

        _umThread = new Thread(() => {
            try {
                string umSessionName = "DeepSensor_UserMode";
                if (TraceEventSession.GetActiveSessionNames().Contains(umSessionName)) {
                    using (var old = new TraceEventSession(umSessionName)) { old.Stop(true); }
                }

                using (var userSession = new TraceEventSession(umSessionName)) {
                    userSession.EnableProvider(Guid.Parse("1418ef04-b0b4-4623-bf7e-d74ab47bbdaa")); // WMI
                    userSession.EnableProvider(Guid.Parse("a0c1853b-5c40-4b15-8766-3cf1c58f985a")); // PowerShell

                    userSession.Source.Dynamic.All += delegate (TraceEvent data) {
                        // PowerShell Script Block Routing
                        if (data.ProviderName == "Microsoft-Windows-PowerShell") {
                            if ((int)data.ID == 4104) {
                                ParsePowerShellScriptBlock(data);
                            }
                            // Return immediately.
                            return;
                        }

                        // WMI ACTIVITY ROUTING
                        if (data.ProviderName == "Microsoft-Windows-WMI-Activity") {
                            StringBuilder sb = new StringBuilder();
                            if (data.PayloadNames != null) {
                                foreach (string key in data.PayloadNames) {
                                    try { sb.Append($"{data.PayloadString(data.PayloadIndex(key))} "); } catch { }
                                }
                            }
                            string dynamicPayload = sb.ToString();

                            // WMI events often log the calling PID in ClientProcessId
                            int actorPid = data.ProcessID;
                            try {
                                string cpidStr = data.PayloadString(data.PayloadIndex("ClientProcessId"));
                                if (!string.IsNullOrEmpty(cpidStr) && int.TryParse(cpidStr, out int p)) {
                                    actorPid = p;
                                }
                            } catch { }

                            string actorName = GetProcessName(actorPid);
                            if (actorPid == SensorPid) return;

                            var matrix = _activeMatrix;
                            bool ttpMatched = false;
                            TtpRuleMatrix ttpMatrix = _ttpMatrix;

                            if (ttpMatrix.ProcRules != null) {
                                List<HighFidelityTTPRule> matchedTtpRules = new List<HighFidelityTTPRule>();
                                string matchedTrigger = "";

                                for (int i = 0; i < ttpMatrix.ProcRules.Length; i++) {
                                    var rule = ttpMatrix.ProcRules[i];
                                    string trigger = rule.TriggerStrings.FirstOrDefault(t => dynamicPayload.IndexOf(t, StringComparison.OrdinalIgnoreCase) >= 0);

                                    if (trigger != null) {
                                        if (rule.actor_process == "**" || actorName.Equals(rule.actor_process, StringComparison.OrdinalIgnoreCase)) {
                                            bool confirmed = true;
                                            if (rule.ExclusionStrings.Any(ex => dynamicPayload.IndexOf(ex, StringComparison.OrdinalIgnoreCase) >= 0)) confirmed = false;
                                            if (confirmed && rule.ExcludePaths.Any(ex => dynamicPayload.IndexOf(ex, StringComparison.OrdinalIgnoreCase) >= 0)) confirmed = false;
                                            if (confirmed && rule.ExcludeTargets.Any(ex => dynamicPayload.IndexOf(ex, StringComparison.OrdinalIgnoreCase) >= 0)) confirmed = false;
                                            if (confirmed && rule.ExcludeTargetValues.Any(ex => dynamicPayload.IndexOf(ex, StringComparison.OrdinalIgnoreCase) >= 0)) confirmed = false;
                                            if (confirmed && rule.ExcludeActorCmds.Any(ex => dynamicPayload.IndexOf(ex, StringComparison.OrdinalIgnoreCase) >= 0)) confirmed = false;
                                            if (confirmed && rule.ExcludeActors.Any(ex => actorName.IndexOf(ex, StringComparison.OrdinalIgnoreCase) >= 0)) confirmed = false;

                                            if (confirmed) {
                                                matchedTtpRules.Add(rule);
                                                if (matchedTrigger == "") matchedTrigger = trigger;
                                            }
                                        }
                                    }
                                }

                                if (matchedTtpRules.Count > 0) {
                                    string alertMessage = $"[TTP] {matchedTtpRules[0].signature_name} | {matchedTtpRules[0].tactic} | {matchedTtpRules[0].technique}";
                                    if (matchedTtpRules.Count > 1) alertMessage = "[TTP] Multiple WMI Rules Matched, Cannot Attribute to Specific Rule";

                                    EnqueueTtpAlert("AdvancedDetection", actorName, "Unknown", actorPid, 0, data.ThreadID, dynamicPayload, alertMessage, matchedTrigger, matchedTtpRules[0]);
                                    ttpMatched = true;
                                }
                            }

                            if (!ttpMatched) {
                                List<SigmaRule> matchedSigmaRules = new List<SigmaRule>();

                                for (int i = 0; i < matrix.WmiRules.Length; i++) {
                                    var rule = matrix.WmiRules[i];

                                    if (EvaluateSigmaRule(rule, dynamicPayload, "", actorName, "", "")) {
                                        matchedSigmaRules.Add(rule);
                                    }
                                }

                                foreach (var rule in matchedSigmaRules) {
                                    EnqueueAlert("Sigma_Match", "WMI_Activity", actorName, "Unknown", actorPid, 0, data.ThreadID, dynamicPayload, "", "Suspicious WMI Execution", rule.title, rule.severity, rule.tags);
                                }
                            }
                        }
                    };
                    userSession.Source.Process();
                }
            } catch (Exception ex) { EnqueueDiag($"USER-MODE ETW CRASH: {ex.Message}"); }
        });
        _umThread.IsBackground = true;
        _umThread.Start();
    }

    [System.Runtime.CompilerServices.MethodImpl(System.Runtime.CompilerServices.MethodImplOptions.NoInlining)]
    private static void RunEtwCore() {
        string sessionName = KernelTraceEventParser.KernelSessionName;
        if (TraceEventSession.GetActiveSessionNames().Contains(sessionName)) {
            using (var old = new TraceEventSession(sessionName)) { old.Stop(true); }
        }

        _session = new TraceEventSession(sessionName);
        _lastEventsLost = 0;
        EnqueueDiag($"TraceEventSession bound: {sessionName}");

        var kernelKeywords = KernelTraceEventParser.Keywords.Process | KernelTraceEventParser.Keywords.Registry |
            KernelTraceEventParser.Keywords.FileIOInit | KernelTraceEventParser.Keywords.FileIO |
            KernelTraceEventParser.Keywords.ImageLoad | KernelTraceEventParser.Keywords.Memory |
            KernelTraceEventParser.Keywords.NetworkTCPIP;

        _session.EnableKernelProvider(kernelKeywords);

        _session.Source.Kernel.ImageLoad += delegate (ImageLoadTraceData data) {
            try {
                string image = GetProcessName(data.ProcessID);
                if (data.ProcessID == SensorPid) return;

                string path = ResolveDosPath(data.FileName ?? "");
                if (!string.IsNullOrEmpty(ToolkitDirectory) && path.IndexOf(ToolkitDirectory, StringComparison.OrdinalIgnoreCase) >= 0) {
                    return;
                }

                if (!_yaraScanQueue.IsAddingCompleted && !string.IsNullOrEmpty(path)) {
                    if (path.IndexOf("C:\\Windows\\System32\\", StringComparison.OrdinalIgnoreCase) < 0 &&
                        path.IndexOf("C:\\Windows\\SysWOW64\\", StringComparison.OrdinalIgnoreCase) < 0) {

                        _yaraScanQueue.Add(path);
                    }
                }

                var matrix = _activeMatrix;
                bool ttpMatched = false;
                TtpRuleMatrix ttpMatrix = _ttpMatrix;

                if (ttpMatrix.ImgRules != null) {
                    List<HighFidelityTTPRule> matchedTtpRules = new List<HighFidelityTTPRule>();
                    string matchedTrigger = "";

                    for (int i = 0; i < ttpMatrix.ImgRules.Length; i++) {
                        var rule = ttpMatrix.ImgRules[i];

                        string trigger = rule.TriggerStrings.FirstOrDefault(t => path.IndexOf(t, StringComparison.OrdinalIgnoreCase) >= 0);

                        if (trigger != null) {
                            if (rule.actor_process == "**" || image.Equals(rule.actor_process, StringComparison.OrdinalIgnoreCase)) {

                                bool isExcluded = false;

                                if (rule.ExclusionStrings.Any(ex => path.IndexOf(ex, StringComparison.OrdinalIgnoreCase) >= 0)) isExcluded = true;
                                if (!isExcluded && rule.ExcludePaths.Any(ex => path.IndexOf(ex, StringComparison.OrdinalIgnoreCase) >= 0)) isExcluded = true;
                                if (!isExcluded && rule.ExcludeTargets.Any(ex => path.IndexOf(ex, StringComparison.OrdinalIgnoreCase) >= 0)) isExcluded = true;
                                if (!isExcluded && rule.ExcludeTargetValues.Any(ex => path.IndexOf(ex, StringComparison.OrdinalIgnoreCase) >= 0)) isExcluded = true;
                                if (!isExcluded && rule.ExcludeActorCmds.Any(ex => path.IndexOf(ex, StringComparison.OrdinalIgnoreCase) >= 0)) isExcluded = true;
                                if (!isExcluded && rule.ExcludeActors.Any(ex => image.IndexOf(ex, StringComparison.OrdinalIgnoreCase) >= 0)) isExcluded = true;

                                if (!isExcluded) {
                                    matchedTtpRules.Add(rule);
                                    if (string.IsNullOrEmpty(matchedTrigger)) matchedTrigger = trigger; // Capture the first trigger that matched
                                }
                            }
                        }
                    }

                    if (matchedTtpRules.Count > 0) {
                        string alertMessage = $"TTP Match: {matchedTtpRules[0].signature_name}";
                        if (matchedTtpRules.Count > 1) alertMessage = "TTP SIG Parsed From Multiple Rules, Cannot Attribute to Specific Rule - Check Rules";

                        EnqueueTtpAlert("AdvancedDetection", image, "Unknown", data.ProcessID, 0, data.ThreadID, path, alertMessage, matchedTrigger, matchedTtpRules[0]);
                        ttpMatched = true;
                    }
                }

                if (!ttpMatched) {
                    List<SigmaRule> matchedSigmaRules = new List<SigmaRule>();

                    string sigmaImage = image.StartsWith("\\") ? image : "\\" + image;
                    for (int i = 0; i < matrix.ImgRules.Length; i++) {
                        var rule = matrix.ImgRules[i];

                        if (EvaluateSigmaRule(rule, "", path, sigmaImage, "", "")) {
                            matchedSigmaRules.Add(rule);
                        }
                    }

                    foreach (var mRule in matchedSigmaRules) {
                        string cacheRuleName = mRule.id;
                        int bracketIdx = cacheRuleName.IndexOf('[');
                        if (bracketIdx >= 0) cacheRuleName = cacheRuleName.Substring(0, bracketIdx).Trim();
                        string cacheKey = $"{image}|{cacheRuleName}";

                        if (!SuppressedSigmaRules.ContainsKey(cacheRuleName) && !SuppressedProcessRules.ContainsKey(cacheKey)) {
                            EnqueueAlert("Sigma_Match", "Image_Load", image, "", data.ProcessID, 0, data.ThreadID, path, "", "Suspicious Module Load", mRule.title, mRule.severity, mRule.tags);
                            SuppressProcessRule(image, cacheRuleName);
                        } else {
                            string jsonEvent = BuildEnrichedJson("UEBA_Audit", "Suppressed_Rule_Hit", image, "", data.ProcessID, 0, data.ThreadID, path, "", path, mRule.id, "", mRule.title, mRule.severity, mRule.tags);

                            if (jsonEvent != null && _aggregator != null) {
                                _aggregator.AddEvent(jsonEvent, "", image, "Suppressed_Rule_Hit", mRule.id, path, path, data.ThreadID, GetEventUser(data.ProcessID), mRule.title, "", "", "", mRule.severity);
                            }
                        }
                    }
                }
                EnqueueRaw("ImageLoad", image, "Unknown", path, "", data.ProcessID, data.ThreadID);
            } catch { }
        };

        _session.Source.Kernel.TcpIpConnect += delegate (TcpIpConnectTraceData data) {
            try {
                if (data.ProcessID == SensorPid) return;
                string image = GetProcessName(data.ProcessID);

                string destIp = data.daddr.ToString();
                int destPort = data.dport;

                if (destIp == "127.0.0.1" || destIp == "::1") return;

                var matrix = _activeMatrix;
                bool ttpMatched = false;
                TtpRuleMatrix ttpMatrix = _ttpMatrix;

                if (ttpMatrix.NetRules != null) {
                    List<HighFidelityTTPRule> matchedTtpRules = new List<HighFidelityTTPRule>();
                    string matchedTrigger = "";

                    for (int i = 0; i < ttpMatrix.NetRules.Length; i++) {
                        var rule = ttpMatrix.NetRules[i];
                        string trigger = rule.TriggerStrings.FirstOrDefault(t => destIp.IndexOf(t, StringComparison.OrdinalIgnoreCase) >= 0 || destPort.ToString() == t);

                        if (trigger != null) {
                            if (rule.actor_process == "**" || image.Equals(rule.actor_process, StringComparison.OrdinalIgnoreCase)) {
                                matchedTtpRules.Add(rule);
                                if (string.IsNullOrEmpty(matchedTrigger)) matchedTrigger = trigger;
                            }
                        }
                    }

                    if (matchedTtpRules.Count > 0) {
                        string alertMessage = $"TTP Match: {matchedTtpRules[0].signature_name}";
                        EnqueueTtpAlert("AdvancedDetection", image, "Unknown", data.ProcessID, 0, data.ThreadID, destIp, alertMessage, matchedTrigger, matchedTtpRules[0]);
                        ttpMatched = true;
                    }
                }

                if (!ttpMatched) {
                    List<SigmaRule> matchedSigmaRules = new List<SigmaRule>();

                    for (int i = 0; i < matrix.NetRules.Length; i++) {
                        var rule = matrix.NetRules[i];
                        if (EvaluateSigmaRule(rule, destIp, destPort.ToString(), image, "", "")) {
                            matchedSigmaRules.Add(rule);
                        }
                    }

                    foreach (var mRule in matchedSigmaRules) {
                        string cacheRuleName = mRule.id;
                        int bracketIdx = cacheRuleName.IndexOf('[');
                        if (bracketIdx >= 0) cacheRuleName = cacheRuleName.Substring(0, bracketIdx).Trim();
                        string cacheKey = $"{image}|{cacheRuleName}";

                        if (!SuppressedSigmaRules.ContainsKey(cacheRuleName) && !SuppressedProcessRules.ContainsKey(cacheKey)) {
                            string jsonEvent = BuildEnrichedJson("Sigma_Match", "Network_Connection", image, "", data.ProcessID, 0, data.ThreadID, destIp, "Suspicious Outbound Connection", destPort.ToString(), mRule.id, mRule.title, mRule.title, mRule.severity, mRule.tags, destIp, destPort);
                            if (jsonEvent != null) { SafeEnqueueEvent(jsonEvent); }
                            SuppressProcessRule(image, cacheRuleName);
                        } else {
                            string jsonEvent = BuildEnrichedJson("UEBA_Audit", "Suppressed_Rule_Hit", image, "", data.ProcessID, 0, data.ThreadID, destIp, "", destPort.ToString(), mRule.id, "", mRule.title, mRule.severity, mRule.tags, destIp, destPort);
                            if (jsonEvent != null && _aggregator != null) {
                                _aggregator.AddEvent(jsonEvent, "", image, "Suppressed_Rule_Hit", mRule.id, destIp, destPort.ToString(), data.ThreadID, GetEventUser(data.ProcessID), mRule.title, "", "", "", mRule.severity);
                            }
                        }
                    }
                }

                string rawJson = BuildEnrichedJson("RawEvent", "NetworkConnect", image, "", data.ProcessID, 0, data.ThreadID, "", "", "", "NetworkConnect", "", "", "", "", destIp, destPort);
                if (rawJson != null && _aggregator != null) {
                    _aggregator.AddEvent(rawJson, "", image, "NetworkConnect", "", destIp, destPort.ToString(), data.ThreadID, GetEventUser(data.ProcessID));
                }

            } catch { }
        };

        _session.Source.Kernel.StackWalkStack += delegate (StackWalkStackTraceData data) {
            if (!ProcessModules.TryGetValue(data.ProcessID, out var modules)) return;
            int unbackedFrames = 0, forgedReturns = 0;

            for (int i = 0; i < data.FrameCount; i++) {
                ulong instructionPointer = data.InstructionPointer(i);
                bool isBacked = false;

                // O(log N) Binary Search across the lock-free array
                int left = 0, right = modules.Length - 1;
                while (left <= right) {
                    int mid = left + (right - left) / 2;
                    if (instructionPointer >= modules[mid].BaseAddress && instructionPointer <= modules[mid].EndAddress) {
                        isBacked = true;
                        break;
                    }
                    if (instructionPointer < modules[mid].BaseAddress) right = mid - 1;
                    else left = mid + 1;
                }

                if (!isBacked) {
                    unbackedFrames++;
                    if (IsForgedReturnAddress(data.ProcessID, instructionPointer)) forgedReturns++;
                }
            }

            if (unbackedFrames >= 2 || forgedReturns > 0) {
                EnqueueAlert("StaticAlert", "StackSpoofDetected", GetProcessName(data.ProcessID), "Unknown", data.ProcessID, 0, data.ThreadID, "", $"{unbackedFrames} unbacked frames | {forgedReturns} forged returns");
            }
        };

        _session.Source.Kernel.ProcessStart += delegate (ProcessTraceData data) {
            try {
                string path = ResolveDosPath(data.ImageFileName ?? "");
                string cmd = data.CommandLine ?? "";
                string image = data.ImageFileName ?? "";

                if (path.Contains("\\")) image = path.Substring(path.LastIndexOf('\\') + 1);

                ProcessCache[data.ProcessID] = image;
                ProcessStartTime[data.ProcessID] = DateTime.UtcNow;

                if (data.ProcessID == SensorPid || data.ParentID == SensorPid) return;

                if (!string.IsNullOrEmpty(ToolkitDirectory) &&
                   (path.IndexOf(ToolkitDirectory, StringComparison.OrdinalIgnoreCase) >= 0 ||
                    cmd.IndexOf(ToolkitDirectory, StringComparison.OrdinalIgnoreCase) >= 0)) {
                    return;
                }

                if (cmd.IndexOf("logman", StringComparison.OrdinalIgnoreCase) >= 0 && cmd.IndexOf("stop", StringComparison.OrdinalIgnoreCase) >= 0) {
                    EnqueueAlert("T1562.002", "ETWTampering", image, GetProcessName(data.ParentID), data.ProcessID, data.ParentID, data.ThreadID, cmd, $"Attempted to terminate ETW: {cmd}");
                }

                var matrix = _activeMatrix;
                bool ttpMatched = false;
                TtpRuleMatrix ttpMatrix = _ttpMatrix;

                if (ttpMatrix.ProcRules != null) {
                    string parentName = GetProcessName(data.ParentID);
                    List<HighFidelityTTPRule> matchedTtpRules = new List<HighFidelityTTPRule>();
                    string matchedTrigger = "";

                    for (int i = 0; i < ttpMatrix.ProcRules.Length; i++) {
                        var rule = ttpMatrix.ProcRules[i];
                        string trigger = rule.TriggerStrings.FirstOrDefault(t => cmd.IndexOf(t, StringComparison.OrdinalIgnoreCase) >= 0);

                        if (trigger != null) {
                            if (rule.actor_process == "**" ||
                                parentName.Equals(rule.actor_process, StringComparison.OrdinalIgnoreCase) ||
                                image.Equals(rule.actor_process, StringComparison.OrdinalIgnoreCase)) {

                                bool isExcluded = false;

                                if (rule.ExclusionStrings.Any(ex => cmd.IndexOf(ex, StringComparison.OrdinalIgnoreCase) >= 0)) isExcluded = true;
                                if (!isExcluded && rule.ExcludePaths.Any(ex => cmd.IndexOf(ex, StringComparison.OrdinalIgnoreCase) >= 0)) isExcluded = true;
                                if (!isExcluded && rule.ExcludeTargets.Any(ex => cmd.IndexOf(ex, StringComparison.OrdinalIgnoreCase) >= 0)) isExcluded = true;
                                if (!isExcluded && rule.ExcludeTargetValues.Any(ex => cmd.IndexOf(ex, StringComparison.OrdinalIgnoreCase) >= 0)) isExcluded = true;
                                if (!isExcluded && rule.ExcludeActorCmds.Any(ex => cmd.IndexOf(ex, StringComparison.OrdinalIgnoreCase) >= 0)) isExcluded = true;
                                if (!isExcluded && rule.ExcludeActors.Any(ex => parentName.IndexOf(ex, StringComparison.OrdinalIgnoreCase) >= 0 || image.IndexOf(ex, StringComparison.OrdinalIgnoreCase) >= 0)) isExcluded = true;

                                if (!isExcluded) {
                                    matchedTtpRules.Add(rule);
                                    if (string.IsNullOrEmpty(matchedTrigger)) matchedTrigger = trigger;
                                }
                            }
                        }
                    }

                    if (matchedTtpRules.Count > 0) {
                        string alertMessage = $"TTP Match: {matchedTtpRules[0].signature_name}";
                        if (matchedTtpRules.Count > 1) alertMessage = "TTP SIG Parsed From Multiple Rules, Cannot Attribute to Specific Rule - Check Rules";

                        EnqueueTtpAlert("AdvancedDetection", image, parentName, data.ProcessID, data.ParentID, data.ThreadID, cmd, alertMessage, matchedTrigger, matchedTtpRules[0]);
                        ttpMatched = true;
                    }
                }

                if (!ttpMatched) {
                    List<SigmaRule> matchedSigmaRules = new List<SigmaRule>();
                    string parentName = GetProcessName(data.ParentID);

                    string sigmaImage = image.StartsWith("\\") ? image : "\\" + image;
                    string sigmaParent = parentName.StartsWith("\\") ? parentName : "\\" + parentName;
                    for (int i = 0; i < matrix.ProcRules.Length; i++) {
                        var rule = matrix.ProcRules[i];
                        if (EvaluateSigmaRule(rule, cmd, path, sigmaImage, sigmaParent, "")) {
                            matchedSigmaRules.Add(rule);
                        }
                    }

                    foreach (var mRule in matchedSigmaRules) {
                        string cacheRuleName = mRule.id;
                        int bracketIdx = cacheRuleName.IndexOf('[');
                        if (bracketIdx >= 0) cacheRuleName = cacheRuleName.Substring(0, bracketIdx).Trim();
                        string cacheKey = $"{image}|{cacheRuleName}";

                        if (!SuppressedSigmaRules.ContainsKey(cacheRuleName) && !SuppressedProcessRules.ContainsKey(cacheKey)) {
                            EnqueueAlert("Sigma_Match", "Process_Creation", image, parentName, data.ProcessID, data.ParentID, data.ThreadID, cmd, "", "Suspicious Process", mRule.title, mRule.severity, mRule.tags);
                            SuppressProcessRule(image, cacheRuleName);
                        } else {
                            string jsonEvent = BuildEnrichedJson("UEBA_Audit", "Suppressed_Rule_Hit", image, parentName, data.ProcessID, data.ParentID, data.ThreadID, cmd, "", path, mRule.id, "", mRule.title, mRule.severity, mRule.tags);

                            if (jsonEvent != null && _aggregator != null) {
                                _aggregator.AddEvent(jsonEvent, parentName, image, "Suppressed_Rule_Hit", mRule.id, cmd, path, data.ThreadID, GetEventUser(data.ProcessID), mRule.title, "", "", "", mRule.severity);
                            }
                        }
                    }
                }
                EnqueueRaw("ProcessStart", image, GetProcessName(data.ParentID), "", cmd, data.ProcessID, data.ThreadID);
            } catch (Exception ex) {
                EnqueueDiag($"[ETW ERROR] ProcessStart handler failed: {ex.Message}");
            }
        };

        _session.Source.Kernel.ProcessStop += delegate (ProcessTraceData data) {
            ProcessCache.TryRemove(data.ProcessID, out _);
            ProcessStartTime.TryRemove(data.ProcessID, out _);
            ProcessModules.TryRemove(data.ProcessID, out _);
        };

        _session.Source.Kernel.RegistrySetValue += delegate (RegistryTraceData data) {
            try {
                string image = GetProcessName(data.ProcessID);
                if (data.ProcessID == SensorPid) return;

                string keyName = data.KeyName ?? "";
                string valName = data.ValueName ?? "";
                string fullReg = keyName + "\\" + valName;

                if (fullReg.StartsWith("\\REGISTRY\\MACHINE", StringComparison.OrdinalIgnoreCase)) {
                    fullReg = fullReg.Replace("\\REGISTRY\\MACHINE", "HKEY_LOCAL_MACHINE");
                }
                else if (fullReg.StartsWith("\\REGISTRY\\USER\\S-1-5", StringComparison.OrdinalIgnoreCase)) {
                    int nextSlash = fullReg.IndexOf('\\', 15);
                    if (nextSlash > 0) fullReg = "HKEY_CURRENT_USER" + fullReg.Substring(nextSlash);
                    else fullReg = "HKEY_CURRENT_USER";
                }

                var matrix = _activeMatrix;
                bool ttpMatched = false;
                TtpRuleMatrix ttpMatrix = _ttpMatrix;

                if (ttpMatrix.RegRules != null) {
                    List<HighFidelityTTPRule> matchedTtpRules = new List<HighFidelityTTPRule>();
                    string matchedTrigger = "";

                    for (int i = 0; i < ttpMatrix.RegRules.Length; i++) {
                        var rule = ttpMatrix.RegRules[i];
                        string trigger = rule.TriggerStrings.FirstOrDefault(t => fullReg.IndexOf(t, StringComparison.OrdinalIgnoreCase) >= 0);

                        if (trigger != null) {
                            if (rule.actor_process == "**" || image.Equals(rule.actor_process, StringComparison.OrdinalIgnoreCase)) {

                                bool isExcluded = false;

                                if (rule.ExclusionStrings.Any(ex => fullReg.IndexOf(ex, StringComparison.OrdinalIgnoreCase) >= 0)) isExcluded = true;
                                if (!isExcluded && rule.ExcludePaths.Any(ex => fullReg.IndexOf(ex, StringComparison.OrdinalIgnoreCase) >= 0)) isExcluded = true;
                                if (!isExcluded && rule.ExcludeTargets.Any(ex => fullReg.IndexOf(ex, StringComparison.OrdinalIgnoreCase) >= 0)) isExcluded = true;
                                if (!isExcluded && rule.ExcludeTargetValues.Any(ex => fullReg.IndexOf(ex, StringComparison.OrdinalIgnoreCase) >= 0)) isExcluded = true;
                                if (!isExcluded && rule.ExcludeActorCmds.Any(ex => fullReg.IndexOf(ex, StringComparison.OrdinalIgnoreCase) >= 0)) isExcluded = true;
                                if (!isExcluded && rule.ExcludeActors.Any(ex => image.IndexOf(ex, StringComparison.OrdinalIgnoreCase) >= 0)) isExcluded = true;

                                if (!isExcluded) {
                                    matchedTtpRules.Add(rule);
                                    if (string.IsNullOrEmpty(matchedTrigger)) matchedTrigger = trigger;
                                }
                            }
                        }
                    }

                    if (matchedTtpRules.Count > 0) {
                        string alertMessage = $"TTP Match: {matchedTtpRules[0].signature_name}";
                        if (matchedTtpRules.Count > 1) alertMessage = "TTP SIG Parsed From Multiple Rules, Cannot Attribute to Specific Rule - Check Rules";

                        EnqueueTtpAlert("AdvancedDetection", image, "Unknown", data.ProcessID, 0, data.ThreadID, fullReg, alertMessage, matchedTrigger, matchedTtpRules[0]);
                        ttpMatched = true;
                    }
                }

                if (!ttpMatched) {
                    List<SigmaRule> matchedSigmaRules = new List<SigmaRule>();

                    string sigmaImage = image.StartsWith("\\") ? image : "\\" + image;
                    for (int i = 0; i < matrix.RegRules.Length; i++) {
                        var rule = matrix.RegRules[i];
                        if (EvaluateSigmaRule(rule, "", "", sigmaImage, "", fullReg)) {
                            matchedSigmaRules.Add(rule);
                        }
                    }

                    foreach (var mRule in matchedSigmaRules) {
                        string cacheRuleName = mRule.id;
                        int bracketIdx = cacheRuleName.IndexOf('[');
                        if (bracketIdx >= 0) cacheRuleName = cacheRuleName.Substring(0, bracketIdx).Trim();
                        string cacheKey = $"{image}|{cacheRuleName}";

                        if (!SuppressedSigmaRules.ContainsKey(cacheRuleName) && !SuppressedProcessRules.ContainsKey(cacheKey)) {
                            EnqueueAlert("Sigma_Match", "Registry_Event", image, "", data.ProcessID, 0, data.ThreadID, fullReg, "", "Suspicious Registry Modification", mRule.title, mRule.severity, mRule.tags);
                            SuppressProcessRule(image, cacheRuleName);
                        } else {
                            string jsonEvent = BuildEnrichedJson("UEBA_Audit", "Suppressed_Rule_Hit", image, "", data.ProcessID, 0, data.ThreadID, fullReg, "", fullReg, mRule.id, "", mRule.title, mRule.severity, mRule.tags);

                            if (jsonEvent != null && _aggregator != null) {
                                _aggregator.AddEvent(jsonEvent, "", image, "Suppressed_Rule_Hit", mRule.id, fullReg, fullReg, data.ThreadID, GetEventUser(data.ProcessID), mRule.title, "", "", "", mRule.severity);
                            }
                        }
                    }
                }
                EnqueueRaw("RegistryWrite", image, "Unknown", fullReg, "", data.ProcessID, data.ThreadID);
            } catch { }
        };

        _session.Source.Kernel.FileIOCreate += delegate (FileIOCreateTraceData data) {
            try {
                string image = GetProcessName(data.ProcessID);
                if (data.ProcessID == SensorPid) return;

                string path = ResolveDosPath(data.FileName ?? "");
                if (!string.IsNullOrEmpty(ToolkitDirectory) && path.IndexOf(ToolkitDirectory, StringComparison.OrdinalIgnoreCase) >= 0) {
                        return;
                    }

                if (!_yaraScanQueue.IsAddingCompleted && !string.IsNullOrEmpty(path)) {
                    if (path.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) ||
                        path.EndsWith(".dll", StringComparison.OrdinalIgnoreCase) ||
                        path.EndsWith(".ps1", StringComparison.OrdinalIgnoreCase) ||
                        path.EndsWith(".vbs", StringComparison.OrdinalIgnoreCase) ||
                        path.EndsWith(".bat", StringComparison.OrdinalIgnoreCase)) {

                        _yaraScanQueue.Add(path);
                    }
                }

                var matrix = _activeMatrix;
                bool ttpMatched = false;
                TtpRuleMatrix ttpMatrix = _ttpMatrix;

                if (ttpMatrix.FileRules != null) {
                    List<HighFidelityTTPRule> matchedTtpRules = new List<HighFidelityTTPRule>();
                    string matchedTrigger = "";

                    for (int i = 0; i < ttpMatrix.FileRules.Length; i++) {
                        var rule = ttpMatrix.FileRules[i];
                        string trigger = rule.TriggerStrings.FirstOrDefault(t => path.IndexOf(t, StringComparison.OrdinalIgnoreCase) >= 0);

                        if (trigger != null) {
                            if (rule.actor_process == "**" || image.Equals(rule.actor_process, StringComparison.OrdinalIgnoreCase)) {

                                bool isExcluded = false;

                                if (rule.ExclusionStrings.Any(ex => path.IndexOf(ex, StringComparison.OrdinalIgnoreCase) >= 0)) isExcluded = true;
                                if (!isExcluded && rule.ExcludePaths.Any(ex => path.IndexOf(ex, StringComparison.OrdinalIgnoreCase) >= 0)) isExcluded = true;
                                if (!isExcluded && rule.ExcludeTargets.Any(ex => path.IndexOf(ex, StringComparison.OrdinalIgnoreCase) >= 0)) isExcluded = true;
                                if (!isExcluded && rule.ExcludeTargetValues.Any(ex => path.IndexOf(ex, StringComparison.OrdinalIgnoreCase) >= 0)) isExcluded = true;
                                if (!isExcluded && rule.ExcludeActorCmds.Any(ex => path.IndexOf(ex, StringComparison.OrdinalIgnoreCase) >= 0)) isExcluded = true;
                                if (!isExcluded && rule.ExcludeActors.Any(ex => image.IndexOf(ex, StringComparison.OrdinalIgnoreCase) >= 0)) isExcluded = true;

                                if (!isExcluded) {
                                    matchedTtpRules.Add(rule);
                                    if (string.IsNullOrEmpty(matchedTrigger)) matchedTrigger = trigger;
                                }
                            }
                        }
                    }

                    if (matchedTtpRules.Count > 0) {
                        string alertMessage = $"TTP Match: {matchedTtpRules[0].signature_name}";
                        if (matchedTtpRules.Count > 1) alertMessage = "TTP SIG Parsed From Multiple Rules, Cannot Attribute to Specific Rule - Check Rules";

                        EnqueueTtpAlert("AdvancedDetection", image, "Unknown", data.ProcessID, 0, data.ThreadID, path, alertMessage, matchedTrigger, matchedTtpRules[0]);
                        ttpMatched = true;
                    }
                }

                if (!ttpMatched) {
                    List<SigmaRule> matchedSigmaRules = new List<SigmaRule>();

                    string sigmaImage = image.StartsWith("\\") ? image : "\\" + image;
                    for (int i = 0; i < matrix.FileRules.Length; i++) {
                        var rule = matrix.FileRules[i];
                        if (EvaluateSigmaRule(rule, "", path, sigmaImage, "", "")) {
                            matchedSigmaRules.Add(rule);
                        }
                    }

                    foreach (var mRule in matchedSigmaRules) {
                        string cacheRuleName = mRule.id;
                        int bracketIdx = cacheRuleName.IndexOf('[');
                        if (bracketIdx >= 0) cacheRuleName = cacheRuleName.Substring(0, bracketIdx).Trim();
                        string cacheKey = $"{image}|{cacheRuleName}";

                        if (!SuppressedSigmaRules.ContainsKey(cacheRuleName) && !SuppressedProcessRules.ContainsKey(cacheKey)) {
                            EnqueueAlert("Sigma_Match", "File_Event", image, "", data.ProcessID, 0, data.ThreadID, path, "", "Suspicious File IO", mRule.title, mRule.severity, mRule.tags);
                            SuppressProcessRule(image, cacheRuleName);
                        } else {
                            string jsonEvent = BuildEnrichedJson("UEBA_Audit", "Suppressed_Rule_Hit", image, "", data.ProcessID, 0, data.ThreadID, path, "", path, mRule.id, "", mRule.title, mRule.severity, mRule.tags);

                            if (jsonEvent != null && _aggregator != null) {
                                _aggregator.AddEvent(jsonEvent, "", image, "Suppressed_Rule_Hit", mRule.id, path, path, data.ThreadID, GetEventUser(data.ProcessID), mRule.title, "", "", "", mRule.severity);
                            }
                        }
                    }
                }
                EnqueueRaw("FileIOCreate", image, "Unknown", path, "", data.ProcessID, data.ThreadID);
            } catch { }
        };

        _session.Source.Kernel.FileIOWrite += delegate (FileIOReadWriteTraceData data) {
            if (data.ProcessID == SensorPid) return;

            string path = ResolveDosPath(data.FileName ?? "");
            if (!string.IsNullOrEmpty(ToolkitDirectory) && path.IndexOf(ToolkitDirectory, StringComparison.OrdinalIgnoreCase) >= 0) {
                return;
            }

            EnqueueRaw("FileIOWrite", GetProcessName(data.ProcessID), "", path, "", data.ProcessID, data.ThreadID);
        };

        _session.Source.Kernel.VirtualMemAlloc += delegate (VirtualAllocTraceData data) {
            int flags = (int)data.Flags;
            // Catch BOTH 0x40 (PAGE_EXECUTE_READWRITE) and 0x20 (PAGE_EXECUTE_READ)
            // This captures the exact moment RW memory is transitioned to RX for execution
            if (flags == 0x40 || flags == 0x20) {

                // Do not scan our own memory allocations
                if (data.ProcessID != SensorPid && data.ProcessID != 0) {
                    ulong baseAddr = Convert.ToUInt64(data.PayloadByName("BaseAddress"));
                    ulong regSize  = Convert.ToUInt64(data.PayloadByName("RegionSize"));

                    // 1. Dump the specific RWX shellcode to disk
                    // 2. Scan it with the Context-Aware YARA matrices
                    // 3. Strip the memory of executable permissions (PAGE_NOACCESS)
                    string yaraResult = NeuterAndDumpPayload(data.ProcessID, baseAddr, regSize);

                    if (yaraResult != "NoSignatureMatch" && yaraResult != "HandleAccessDenied") {
                        // We got a YARA hit! Quarantine the thread that injected it.
                        bool neutralized = QuarantineNativeThread(data.ThreadID, data.ProcessID);
                        EnqueueAlert("T1055", "YaraPayloadAttribution", GetProcessName(data.ProcessID), "Unknown", data.ProcessID, 0, data.ThreadID, "", $"YARA Hit: {yaraResult} | Thread Frozen: {neutralized}");
                    }
                }
            }
        };

        // Telemetry Blinding & Heartbeat - Background Watchdog for ETW Buffer Exhaustion
        Task.Run(async () => {
            int heartbeatCounter = 0;

            while (IsSessionHealthy()) {
                await Task.Delay(2000); // Check every 2 seconds

                if (_session != null && _session.EventsLost > _lastEventsLost) {
                    int dropped = _session.EventsLost - _lastEventsLost;
                    _lastEventsLost = _session.EventsLost;

                    EventQueue.Enqueue($"{{\"Provider\":\"DiagLog\", \"Message\":\"SENSOR_BLINDING_DETECTED:{dropped}\"}}");
                }

                heartbeatCounter++;
                if (heartbeatCounter >= 15) {
                    EventQueue.Enqueue("{\"Provider\":\"HealthCheck\"}");
                    heartbeatCounter = 0;
                }
            }
        });

        _session.Source.Process();
    }

    // Watchdog state
    private static int _lastEventsLost = 0;

    public static bool IsSessionHealthy() {
        if (_session == null) return false;
        try { return _session.Source != null; } catch { return false; }
    }

    public static void StopSession() {
        if (_session != null) {
            Task.Run(() => {
                try {
                    _session.Stop();
                    _session.Dispose();
                } catch { }
            }).Wait(1000);
            _session = null;
        }

        Task.Run(() => {
            try {
                // Query the OS for all currently running ETW trace sessions
                var activeSessions = TraceEventSession.GetActiveSessionNames();
                var sessionsToKill = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

                // Add the Kernel Logger if it is currently running
                string kernelSession = KernelTraceEventParser.KernelSessionName;
                if (activeSessions.Contains(kernelSession)) {
                    sessionsToKill.Add(kernelSession);
                }

                // Add ANY session that starts with "DeepSensor" (Catches UserMode, leaks, etc.)
                foreach (string sessionName in activeSessions) {
                    if (sessionName.StartsWith("DeepSensor", StringComparison.OrdinalIgnoreCase)) {
                        sessionsToKill.Add(sessionName);
                    }
                }

                // Execute targeted teardown
                foreach (string targetSession in sessionsToKill) {
                    try {
                        using (var orphaned = new TraceEventSession(targetSession)) {
                            orphaned.Stop(true); // true = forceful stop
                        }
                    } catch {
                        // Silently swallow access/not-found errors during teardown
                    }
                }
            } catch { }
        }).Wait(2000); // Allow up to 2 seconds for kernel objects to release

        if (_umThread != null && _umThread.IsAlive) {
            _umThread.Join(500);
        }
    }

    public static void TeardownEngine() {
        _mlWorkQueue.CompleteAdding();
        _mlCancelSource.Cancel();

        if (_mlConsumerTask != null) { _mlConsumerTask.Wait(2000); }

        if (_mlEnginePtr != IntPtr.Zero) {
            teardown_engine(_mlEnginePtr);
            _mlEnginePtr = IntPtr.Zero;
            EnqueueDiag("[ML ENGINE] Native Rust DLL safely unloaded and DB flushed.");
        }

        foreach (var rules in YaraMatrices.Values) {
            try { rules.Dispose(); } catch {}
        }
        YaraMatrices.Clear();
        if (_yaraContext != null) { _yaraContext.Dispose(); _yaraContext = null; }
    }

    private static string GetProcessName(int pid) {
        return ProcessCache.ContainsKey(pid) ? ProcessCache[pid] : pid.ToString();
    }

    private static string GetEventUser(int pid) {
        if (ProcessUserCache.TryGetValue(pid, out string user)) return user;

        user = "UNKNOWN";
        try {
            using (var searcher = new System.Management.ManagementObjectSearcher($"Select * From Win32_Process Where ProcessID = {pid}")) {
                foreach (System.Management.ManagementObject mo in searcher.Get()) {
                    string[] ownerInfo = new string[2];
                    mo.InvokeMethod("GetOwner", (object[])ownerInfo);
                    if (ownerInfo[0] != null) {
                        user = string.IsNullOrWhiteSpace(ownerInfo[1]) ? ownerInfo[0] : $"{ownerInfo[1]}\\{ownerInfo[0]}";
                    }
                    break;
                }
            }
        } catch { user = "NT AUTHORITY\\SYSTEM"; }

        ProcessUserCache.TryAdd(pid, user);
        return user;
    }

    // EnqueueAlert with Fingerprinting + Full Config Exclusions
    public static void EnqueueAlert(string category, string eventType, string process, string parentProcess, int pid, int parentPid, int tid, string cmdline, string details, string matchedIndicator = "", string signatureName = "", string severity = "", string tags = "") {

        string jsonEvent = BuildEnrichedJson(category, eventType, process, parentProcess, pid, parentPid, tid, cmdline, details, "", "", matchedIndicator, signatureName, severity, tags);
        if (jsonEvent == null) return;

        Interlocked.Increment(ref TotalAlertsGenerated);

        try {
            if (_mlEnginePtr != IntPtr.Zero) {
                if (!_mlWorkQueue.IsAddingCompleted)
                    _mlWorkQueue.Add(jsonEvent);
            } else {
                EventQueue.Enqueue(jsonEvent);
            }
        } catch (InvalidOperationException) { }
    }

    public static void EnqueueTtpAlert(string eventType, string process, string parentProcess, int pid, int parentPid, int tid, string cmdline, string details, string matchedIndicator, HighFidelityTTPRule rule)
    {
        if (_mlEnginePtr == IntPtr.Zero) return;

        string json = $@"{{
            ""Category"":""TTP_Match"",
            ""Type"":""{eventType}"",
            ""Process"":""{JsonEscape(process)}"",
            ""Parent"":""{JsonEscape(parentProcess)}"",
            ""PID"":{pid},
            ""ParentPID"":{parentPid},
            ""TID"":{tid},
            ""Cmd"":""{JsonEscape(cmdline)}"",
            ""Details"":""{JsonEscape(details)}"",
            ""ComputerName"":""{HostComputerName}"",
            ""IP"":""{HostIP}"",
            ""OS"":""{HostOS}"",
            ""SensorUser"":""{SensorUser}"",
            ""EventUser"":""{JsonEscape(GetEventUser(pid))}"",
            ""Destination"":"""",
            ""Port"":0,
            ""MatchedIndicator"":""{JsonEscape(matchedIndicator)}"",
            ""SignatureName"":""{JsonEscape(rule.signature_name)}"",
            ""Tactic"":""{JsonEscape(rule.tactic)}"",
            ""Technique"":""{JsonEscape(rule.technique)}"",
            ""Procedure"":""{JsonEscape(rule.procedure)}"",
            ""Severity"":""{JsonEscape(rule.severity)}""
        }}".Replace("\r", "").Replace("\n", "").Replace("  ", "");

        Interlocked.Increment(ref TotalAlertsGenerated);

        try
        {
            if (!_mlWorkQueue.IsAddingCompleted)
            {
                _mlWorkQueue.Add(json);
            }
        }
        catch (InvalidOperationException) { }
    }

    private static void EnqueueRaw(string type, string process, string parent, string path, string cmd, int pid, int tid) {
        Interlocked.Increment(ref TotalEventsParsed);
        if (_mlEnginePtr == IntPtr.Zero) return;

        string eventUser = GetEventUser(pid);
        string jsonEvent = BuildEnrichedJson("RawEvent", type, process, parent, pid, 0, tid, cmd, "", path, type, "");
        if (jsonEvent == null) return;

        try {
            if (!_mlWorkQueue.IsAddingCompleted) {
                if (_aggregator != null)
                    _aggregator.AddEvent(jsonEvent, parent, process, type, "", cmd, path, tid, eventUser);
                else
                    _mlWorkQueue.Add(jsonEvent);
            }
        } catch (InvalidOperationException) { }
    }
}