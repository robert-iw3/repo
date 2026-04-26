/*=============================================================================================
 * SYSTEM:          Data Sensor
 * COMPONENT:       DataSensor.cs (Unmanaged ETW Listener & Active Defense)
 * AUTHOR:          Robert Weber
 * DESCRIPTION:
 * High-performance ETW engine monitoring File I/O and Network volumetric flow.
 * Incorporates O(1) pre-filtering for trusted processes, lock-free micro-batching
 * via BlockingCollection, and non-blocking I/O file sampling to pass telemetry
 * to the Native Rust ML engine without starving the .NET ThreadPool.
 *============================================================================================*/

using System;
using System.IO;
using System.Linq;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Text;
using System.Threading.Tasks;
using System.Threading;
using System.Runtime.InteropServices;
using System.Security.Principal;
using Microsoft.Diagnostics.Tracing;
using Microsoft.Diagnostics.Tracing.Session;

public class RealTimeDataSensor {

    [DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    static extern bool SetDllDirectory(string lpPathName);

    // --- NATIVE RUST FFI BOUNDARIES ---
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi)]
    public struct FfiPlatformEvent {
        public string timestamp;
        public string user;
        public string process;
        public string filepath;
        public string destination;
        public long bytes;
        public long duration_ms;
    }

    [DllImport("DataSensor_ML.dll", CallingConvention = CallingConvention.Cdecl)]
    private static extern IntPtr init_dlp_engine(string config_json);

    [DllImport("DataSensor_ML.dll", CallingConvention = CallingConvention.Cdecl)]
    private static extern IntPtr process_telemetry_batch(IntPtr engine, string batch_json);

    [DllImport("DataSensor_ML.dll", CallingConvention = CallingConvention.Cdecl)]
    private static extern IntPtr inspect_file_content(IntPtr engine, string file_ext, string filepath, string process_name, string user_name);

    [DllImport("DataSensor_ML.dll", CallingConvention = CallingConvention.Cdecl)]
    private static extern void free_string(IntPtr s);

    [DllImport("DataSensor_ML.dll", CallingConvention = CallingConvention.Cdecl)]
    private static extern void teardown_engine(IntPtr engine);

    private static ConcurrentDictionary<int, string> _pidUserCache = new ConcurrentDictionary<int, string>();

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, int dwProcessId);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    static extern bool OpenProcessToken(IntPtr ProcessHandle, uint DesiredAccess, out IntPtr TokenHandle);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    static extern bool CloseHandle(IntPtr hObject);

    private static BlockingCollection<FfiPlatformEvent> _uebaQueue = new BlockingCollection<FfiPlatformEvent>(100000);
    private static Thread _clipboardWorker;

    private static BlockingCollection<FfiPlatformEvent> _uebaJsonQueue = new BlockingCollection<FfiPlatformEvent>(100000);
    private static Thread _uebaJsonWorker;

    [DllImport("user32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    static extern bool OpenClipboard(IntPtr hWndNewOwner);

    [DllImport("user32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    static extern bool CloseClipboard();

    [DllImport("user32.dll")]
    static extern IntPtr GetClipboardData(uint uFormat);

    [DllImport("user32.dll")]
    static extern IntPtr GetForegroundWindow();

    [DllImport("user32.dll", SetLastError = true)]
    static extern IntPtr GetClipboardOwner();

    [DllImport("user32.dll", SetLastError = true)]
    static extern uint GetWindowThreadProcessId(IntPtr hWnd, out uint lpdwProcessId);

    [DllImport("kernel32.dll")]
    static extern IntPtr GlobalLock(IntPtr hMem);

    [DllImport("kernel32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    static extern bool GlobalUnlock(IntPtr hMem);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern uint QueryDosDevice(string lpDeviceName, StringBuilder lpTargetPath, int ucchMax);

    private static ConcurrentDictionary<string, string> _volumeMap = new ConcurrentDictionary<string, string>(StringComparer.OrdinalIgnoreCase);

    public class DataEvent {
        public string EventType;
        public string ProcessName;
        public string UserName;
        public string RawJson;
    }

    public static ConcurrentQueue<DataEvent> EventQueue = new ConcurrentQueue<DataEvent>();
    private static BlockingCollection<Tuple<string, string, string>> _deepInspectionQueue = new BlockingCollection<Tuple<string, string, string>>(1000);
    private static Thread _inspectionWorker;
    private static HashSet<string> _trustedProcesses = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
    private static IntPtr _mlEnginePtr = IntPtr.Zero;
    private static TraceEventSession _session;
    private static CancellationTokenSource _cts = new CancellationTokenSource();
    private static ConcurrentDictionary<string, DateTime> _lastInspected = new ConcurrentDictionary<string, DateTime>(StringComparer.OrdinalIgnoreCase);
    private static ConcurrentDictionary<string, string> _fileObjectToPath = new ConcurrentDictionary<string, string>();
    private static long _maxInspectionBytes = 150 * 1024 * 1024;
    private static bool _enableUniversalLedger = false;

    public static void InitializeEngine(string configJson, long maxMb, string trustedProcsCsv, bool enableLedger) {
        _enableUniversalLedger = enableLedger;
        _maxInspectionBytes = maxMb * 1024 * 1024;

        if (!string.IsNullOrEmpty(trustedProcsCsv)) {
            foreach (var proc in trustedProcsCsv.Split(',')) {
                _trustedProcesses.Add(proc.Trim());
            }
        }

        if (_volumeMap.IsEmpty) { InitializeVolumeMap(); }

        SetDllDirectory(@"C:\ProgramData\DataSensor\Bin");

        try {
            _mlEnginePtr = init_dlp_engine(configJson);
            if (_mlEnginePtr != IntPtr.Zero) {
                EventQueue.Enqueue(new DataEvent { EventType = "DiagLog", RawJson = "Native Rust ML Engine (FFI) successfully mapped into memory." });
                StartBatchProcessor();
                StartDeepInspectionWorker();
                StartClipboardMonitor();
                if (_enableUniversalLedger) { StartUebaJsonLogger(); }
            } else {
                EventQueue.Enqueue(new DataEvent { EventType = "FATAL", RawJson = "Native FFI Pointer returned null." });
            }
        } catch (Exception ex) {
            EventQueue.Enqueue(new DataEvent { EventType = "FATAL", RawJson = ex.Message });
        }
    }

    private static string GetProcessUser(int pid) {
        if (pid <= 4) return "System";

        if (_pidUserCache.TryGetValue(pid, out string cachedUser)) {
            return cachedUser;
        }

        string userName = "System";
        IntPtr processHandle = IntPtr.Zero;
        IntPtr tokenHandle = IntPtr.Zero;

        try {
            processHandle = OpenProcess(0x1000, false, pid);
            if (processHandle != IntPtr.Zero) {
                if (OpenProcessToken(processHandle, 0x0008, out tokenHandle)) {
                    using (WindowsIdentity wi = new WindowsIdentity(tokenHandle)) {
                        userName = wi.Name;
                        if (userName.Contains("\\")) {
                            userName = userName.Split('\\')[1];
                        }
                    }
                }
            }
        } catch {
        } finally {
            if (tokenHandle != IntPtr.Zero) CloseHandle(tokenHandle);
            if (processHandle != IntPtr.Zero) CloseHandle(processHandle);
        }

        _pidUserCache.TryAdd(pid, userName);
        return userName;
    }

    public static void InitializeVolumeMap() {
        try {
            foreach (string drive in Environment.GetLogicalDrives()) {
                string driveLetter = drive.Substring(0, 2);
                StringBuilder targetPath = new StringBuilder(256);
                if (QueryDosDevice(driveLetter, targetPath, targetPath.Capacity) != 0) {
                    _volumeMap[targetPath.ToString()] = driveLetter;
                }
            }
        } catch (Exception ex) {
            EventQueue.Enqueue(new DataEvent { EventType = "ERROR", RawJson = "Volume Map Init Failed: " + ex.Message });
        }
    }

    public static string ResolveUniversalPath(string ntPath) {
        if (string.IsNullOrEmpty(ntPath)) return "";

        if (!ntPath.StartsWith(@"\device\", StringComparison.OrdinalIgnoreCase)) return ntPath;

        foreach (var kvp in _volumeMap) {
            if (ntPath.StartsWith(kvp.Key, StringComparison.OrdinalIgnoreCase)) {
                return System.Text.RegularExpressions.Regex.Replace(
                    ntPath,
                    "^" + System.Text.RegularExpressions.Regex.Escape(kvp.Key),
                    kvp.Value,
                    System.Text.RegularExpressions.RegexOptions.IgnoreCase
                );
            }
        }
        return ntPath;
    }

    private static string ParseIp(object val) {
        if (val == null) return "";
        string result = "";

        if (val is byte[]) {
            byte[] b = (byte[])val;
            try {
                if (b.Length >= 8 && b[0] == 2 && b[1] == 0) result = new System.Net.IPAddress(new byte[] { b[4], b[5], b[6], b[7] }).ToString();
                else if (b.Length >= 24 && b[0] == 23 && b[1] == 0 && b[18] == 255 && b[19] == 255) result = new System.Net.IPAddress(new byte[] { b[20], b[21], b[22], b[23] }).ToString();
                else if (b.Length == 4 || b.Length == 16) result = new System.Net.IPAddress(b).ToString();
            } catch {}
        }
        else if (val is int || val is uint || val is long) {
            try {
                byte[] bytes = BitConverter.GetBytes(Convert.ToInt64(val));
                result = new System.Net.IPAddress(new byte[] { bytes[0], bytes[1], bytes[2], bytes[3] }).ToString();
            } catch {}
        }
        else { result = val.ToString(); }

        if (result.Contains("::ffff:")) result = result.Replace("::ffff:", "");
        return result;
    }

    private static string FallbackIpExtract(byte[] payload, out string extractedPort) {
        extractedPort = "";
        if (payload == null || payload.Length < 8) return "DECODER_FAILED";
        string lastFound = "DECODER_FAILED";

        for (int i = 0; i < payload.Length - 7; i++) {
            if (payload[i] == 2 && payload[i+1] == 0) {
                if (payload[i+2] == 0 && payload[i+3] == 0) continue;

                int ip1 = payload[i+4]; int ip2 = payload[i+5]; int ip3 = payload[i+6]; int ip4 = payload[i+7];
                if (ip1 == 0 || ip1 == 127 || ip1 == 255) continue;

                string ipStr = ip1 + "." + ip2 + "." + ip3 + "." + ip4;
                lastFound = ipStr;

                if (ip1 == 10 || (ip1 == 192 && ip2 == 168) || (ip1 == 172 && ip2 >= 16 && ip2 <= 31) || (ip1 == 169 && ip2 == 254) || ip1 >= 224) continue;

                extractedPort = ((payload[i+2] << 8) | payload[i+3]).ToString();
                return ipStr;
            }
            else if (i < payload.Length - 23 && payload[i] == 23 && payload[i+1] == 0) {
                if (payload[i+2] == 0 && payload[i+3] == 0) continue;

                if (payload[i+18] == 255 && payload[i+19] == 255) {
                    int ip1 = payload[i+20]; int ip2 = payload[i+21]; int ip3 = payload[i+22]; int ip4 = payload[i+23];
                    if (ip1 == 0 || ip1 == 127 || ip1 == 255) continue;

                    string ipStr = ip1 + "." + ip2 + "." + ip3 + "." + ip4;
                    lastFound = ipStr;

                    if (ip1 == 10 || (ip1 == 192 && ip2 == 168) || (ip1 == 172 && ip2 >= 16 && ip2 <= 31) || (ip1 == 169 && ip2 == 254) || ip1 >= 224) continue;

                    extractedPort = ((payload[i+2] << 8) | payload[i+3]).ToString();
                    return ipStr;
                }
            }
        }
        return lastFound;
    }

    private static void StartBatchProcessor() {
        Task.Run(() => {
            List<FfiPlatformEvent> batch = new List<FfiPlatformEvent>(5000);
            while (!_cts.Token.IsCancellationRequested) {
                try {
                    foreach (var item in _uebaQueue.GetConsumingEnumerable(_cts.Token)) {
                        batch.Add(item);

                        while (batch.Count < 5000 && _uebaQueue.TryTake(out FfiPlatformEvent nextItem)) {
                            batch.Add(nextItem);
                        }

                        if (batch.Count > 0 && _mlEnginePtr != IntPtr.Zero) {
                            System.Text.StringBuilder sb = new System.Text.StringBuilder(batch.Count * 256);
                            sb.Append("[");
                            for (int i = 0; i < batch.Count; i++) {
                                var e = batch[i];
                                string safePath = e.filepath != null ? e.filepath.Replace("\\", "\\\\").Replace("\"", "\\\"") : "";
                                string safeDest = e.destination != null ? e.destination.Replace("\\", "\\\\").Replace("\"", "\\\"") : "";
                                sb.Append($"{{\"timestamp\":\"{e.timestamp}\",\"user\":\"{e.user}\",\"process\":\"{e.process}\",\"filepath\":\"{safePath}\",\"destination\":\"{safeDest}\",\"bytes\":{e.bytes},\"duration_ms\":{e.duration_ms}}}");
                                if (i < batch.Count - 1) sb.Append(",");
                            }
                            sb.Append("]");

                            IntPtr resultPtr = process_telemetry_batch(_mlEnginePtr, sb.ToString());
                            ParseResponse(resultPtr, "UEBA_Engine", "System_ML", 0, "UEBA_ALERT");
                            batch.Clear();
                        }
                    }
                }
                catch (OperationCanceledException) { break; }
                catch (Exception ex) {
                    EventQueue.Enqueue(new DataEvent { EventType = "ERROR", RawJson = "Batch Processor Fault: " + ex.Message });
                    batch.Clear();
                }
            }
        });
    }

    public static void StartClipboardMonitor() {
        _clipboardWorker = new Thread(() => {
            string lastClipboardText = string.Empty;
            while (!_cts.Token.IsCancellationRequested) {
                try {
                    if (OpenClipboard(IntPtr.Zero)) {
                        uint format = 13;
                        IntPtr hData = GetClipboardData(format);
                        if (hData != IntPtr.Zero) {
                            IntPtr pData = GlobalLock(hData);
                            if (pData != IntPtr.Zero) {
                                string currentText = Marshal.PtrToStringUni(pData);
                                GlobalUnlock(hData);

                                if (!string.IsNullOrEmpty(currentText) && currentText != lastClipboardText) {
                                    lastClipboardText = currentText;

                                    string activeProcessName = "Unknown_App";
                                    try {
                                        IntPtr hWnd = GetClipboardOwner();
                                        if (hWnd == IntPtr.Zero) hWnd = GetForegroundWindow();
                                        if (hWnd != IntPtr.Zero) {
                                            GetWindowThreadProcessId(hWnd, out uint pid);
                                            activeProcessName = System.Diagnostics.Process.GetProcessById((int)pid).ProcessName;
                                        }
                                    } catch { }

                                    string tempClipPath = Path.Combine(Path.GetTempPath(), $"clip_buffer_{Guid.NewGuid()}.txt");
                                    File.WriteAllText(tempClipPath, currentText);
                                    if (!_deepInspectionQueue.IsAddingCompleted) {
                                        _deepInspectionQueue.Add(new Tuple<string, string, string>(tempClipPath, activeProcessName, Environment.UserName));
                                    }

                                    var evt = new FfiPlatformEvent {
                                        timestamp = DateTime.Now.ToString("O"),
                                        user = Environment.UserName,
                                        process = activeProcessName,
                                        filepath = "Clipboard_Capture",
                                        destination = "Memory_Buffer",
                                        bytes = currentText.Length * 2,
                                        duration_ms = 1
                                    };

                                    if (!_uebaQueue.IsAddingCompleted) {
                                        _uebaQueue.TryAdd(evt, 0);
                                        _uebaJsonQueue.TryAdd(evt, 0);
                                    }
                                }
                            }
                        }
                        CloseClipboard();
                    }
                } catch { }
                Thread.Sleep(1000);
            }
        });
        _clipboardWorker.SetApartmentState(ApartmentState.STA);
        _clipboardWorker.IsBackground = true;
        _clipboardWorker.Start();
    }

    private static void StartUebaJsonLogger() {
        _uebaJsonWorker = new Thread(() => {
            string logPath = @"C:\ProgramData\DataSensor\Logs\DataSensor_UEBA.jsonl";
            while (!_cts.Token.IsCancellationRequested || _uebaJsonQueue.Count > 0) {
                try {
                    using (FileStream fs = new FileStream(logPath, FileMode.Append, FileAccess.Write, FileShare.ReadWrite, 65536))
                    using (StreamWriter sw = new StreamWriter(fs)) {
                        foreach (var evt in _uebaJsonQueue.GetConsumingEnumerable()) {
                            string safePath = evt.filepath != null ? evt.filepath.Replace("\\", "\\\\").Replace("\"", "\\\"") : "";
                            string safeDest = evt.destination != null ? evt.destination.Replace("\\", "\\\\").Replace("\"", "\\\"") : "";

                            string jsonLine = $"{{\"Timestamp\":\"{evt.timestamp}\", \"User\":\"{evt.user}\", \"Process\":\"{evt.process}\", \"FilePath\":\"{safePath}\", \"Destination\":\"{safeDest}\", \"Bytes\":{evt.bytes}, \"DurationMs\":{evt.duration_ms}}}";
                            sw.WriteLine(jsonLine);
                        }
                    }
                } catch {
                    Thread.Sleep(500);
                }
            }
        });
        _uebaJsonWorker.IsBackground = true;
        _uebaJsonWorker.Start();
    }

    private static void StartDeepInspectionWorker() {
        _inspectionWorker = new Thread(() => {
            foreach (var item in _deepInspectionQueue.GetConsumingEnumerable(_cts.Token)) {
                if (_mlEnginePtr == IntPtr.Zero) continue;

                Task.Run(async () => {
                    try {
                        await Task.Delay(250);
                        FileInfo fi = new FileInfo(item.Item1);

                        if (fi.Length > _maxInspectionBytes || fi.Length == 0) return;

                        string ext = string.IsNullOrEmpty(fi.Extension) ? "" : fi.Extension.ToLowerInvariant();
                        IntPtr resultPtr = inspect_file_content(_mlEnginePtr, ext, item.Item1, item.Item2, item.Item3);
                        ParseResponse(resultPtr, item.Item2, item.Item3, 0, "DLP_ALERT");
                    } catch { }
                });
            }
        });
        _inspectionWorker.IsBackground = true;
        _inspectionWorker.Start();
    }

    private static void ParseResponse(IntPtr resultPtr, string processName, string userName, uint threadId, string defaultAlertType) {
        if (resultPtr != IntPtr.Zero) {
            string resultJson = Marshal.PtrToStringAnsi(resultPtr);
            free_string(resultPtr);

            if (resultJson != null && resultJson.Contains("alert_type")) {
                if (EventQueue.Count < 5000) {
                    EventQueue.Enqueue(new DataEvent {
                        EventType = defaultAlertType,
                        ProcessName = processName,
                        UserName = userName,
                        RawJson = resultJson
                    });
                }
            }
        }
    }

    public static void StartSession() {
        if (_volumeMap.IsEmpty) { InitializeVolumeMap(); }

        Task.Run(() => {
            try {
                if (TraceEventSession.GetActiveSessionNames().Contains("DataSensorRealTimeSession")) {
                    var oldSession = new TraceEventSession("DataSensorRealTimeSession");
                    oldSession.Dispose();
                }

                _session = new TraceEventSession("DataSensorRealTimeSession");

                _session.EnableProvider("Microsoft-Windows-Kernel-Process", TraceEventLevel.Informational, 0x10);
                _session.EnableProvider("Microsoft-Windows-TCPIP", TraceEventLevel.Informational, 0xFFFFFFFF);
                _session.EnableProvider("Microsoft-Windows-DNS-Client");
                _session.EnableProvider("Microsoft-Windows-Kernel-File");

                _session.Source.Dynamic.All += delegate (TraceEvent data) {
                    try {
                        string evName = data.EventName;
                        if (evName == "ThreadWorkOnBehalfUpdate" || evName == "CpuPriorityChange" || evName.StartsWith("Thread") || evName == "ImageLoad" || evName == "ImageUnload") return;

                        // 1. Process Lineage Pre-Caching
                        if (data.ProviderName.Contains("Kernel-Process") && evName.Contains("Start")) {
                            Task.Run(() => {
                                try {
                                    string userName = "System";
                                    IntPtr processHandle = OpenProcess(0x1000, false, data.ProcessID);
                                    if (processHandle != IntPtr.Zero) {
                                        if (OpenProcessToken(processHandle, 0x0008, out IntPtr tokenHandle)) {
                                            using (System.Security.Principal.WindowsIdentity wi = new System.Security.Principal.WindowsIdentity(tokenHandle)) {
                                                userName = wi.Name.Contains("\\") ? wi.Name.Split('\\')[1] : wi.Name;
                                            }
                                            CloseHandle(tokenHandle);
                                        }
                                        CloseHandle(processHandle);
                                    }
                                    _pidUserCache.AddOrUpdate(data.ProcessID, userName, (k, v) => userName);
                                } catch { }
                            });
                        }
                        else if (data.ProviderName.Contains("Kernel-Process") && evName.Contains("Stop")) {
                            _pidUserCache.TryRemove(data.ProcessID, out _);
                        }

                        string procName = string.IsNullOrEmpty(data.ProcessName) ? data.ProcessID.ToString() : data.ProcessName;
                        if (_trustedProcesses.Contains(procName)) return;

                        // 2. File I/O Mapping
                        if (data.ProviderName.Contains("Kernel-File")) {
                            string fileObj = "";
                            try { fileObj = data.PayloadStringByName("FileObject") ?? ""; } catch {}

                            if (evName == "Create" || evName == "NameCreate" || evName == "Rename") {
                                string fileName = "";
                                try { fileName = data.PayloadStringByName("FileName") ?? ""; } catch {}

                                if (!string.IsNullOrEmpty(fileName) && !string.IsNullOrEmpty(fileObj)) {
                                    string dosPath = ResolveUniversalPath(fileName);
                                    if (!string.IsNullOrEmpty(dosPath) && !dosPath.StartsWith(@"\Device\", StringComparison.OrdinalIgnoreCase)) {
                                        _fileObjectToPath[fileObj] = dosPath;
                                    }
                                }
                            }
                            else if (evName == "Write") {
                                if (!string.IsNullOrEmpty(fileObj) && _fileObjectToPath.TryGetValue(fileObj, out string dosPath)) {
                                    long ioSize = 0;
                                    try { ioSize = Convert.ToInt64(data.PayloadByName("IoSize") ?? 0); } catch { }

                                    if (ioSize > 0) {
                                        var evt = new FfiPlatformEvent {
                                            timestamp = DateTime.Now.ToString("O"),
                                            user = GetProcessUser(data.ProcessID),
                                            process = procName,
                                            filepath = dosPath,
                                            destination = "Disk_Write",
                                            bytes = ioSize,
                                            duration_ms = 10
                                        };

                                        if (!_uebaQueue.IsAddingCompleted) {
                                            _uebaQueue.TryAdd(evt, 0);
                                            if (_enableUniversalLedger) { _uebaJsonQueue.TryAdd(evt, 0); }
                                        }
                                    }
                                }
                            }
                            else if (evName == "Close" || evName == "Cleanup") {
                                if (!string.IsNullOrEmpty(fileObj) && _fileObjectToPath.TryGetValue(fileObj, out string dosPath)) {
                                    if (!_lastInspected.TryGetValue(dosPath, out DateTime lastTime) || (DateTime.Now - lastTime).TotalSeconds > 2) {
                                        _lastInspected[dosPath] = DateTime.Now;
                                        if (!_deepInspectionQueue.IsAddingCompleted) {
                                            _deepInspectionQueue.Add(new Tuple<string, string, string>(dosPath, procName, GetProcessUser(data.ProcessID)));
                                        }
                                    }
                                    if (evName == "Close") {
                                        _fileObjectToPath.TryRemove(fileObj, out _);
                                    }
                                }
                            }
                        }

                        // 3. Network & DNS Routing
                        bool isNetworkEvent = data.ProviderName.Contains("TCPIP") || data.ProviderName.Contains("Network");
                        bool isDnsEvent = data.ProviderName.Contains("DNS");

                        if (isNetworkEvent || isDnsEvent) {
                            string destIp = ""; string query = ""; string sizeStr = "0";

                            for (int i = 0; i < data.PayloadNames.Length; i++) {
                                string name = data.PayloadNames[i].ToLower();
                                object pVal = data.PayloadValue(i);

                                if (name == "destinationip" || name == "daddr" || name == "destaddress" || name == "remoteaddress" || name == "destination") {
                                    string parsedIp = ParseIp(pVal);
                                    if (!string.IsNullOrEmpty(parsedIp) && !parsedIp.Contains("EXCEPTION")) { destIp = parsedIp; }
                                }
                                else if (name == "queryname" || name == "query" || name == "qname") {
                                    query = pVal?.ToString() ?? "";
                                }
                                else if (name == "size" || name == "bytessent" || name == "length") {
                                    sizeStr = pVal?.ToString() ?? "0";
                                }
                            }

                            if (isNetworkEvent && string.IsNullOrEmpty(destIp)) {
                                try {
                                    byte[] rawPayload = data.EventData();
                                    string fbPort;
                                    string fbIp = FallbackIpExtract(rawPayload, out fbPort);
                                    if (!string.IsNullOrEmpty(fbIp) && fbIp != "DECODER_FAILED") { destIp = fbIp; }
                                } catch { }
                            }

                            string finalDest = string.IsNullOrEmpty(query) ? destIp : query;
                            if (string.IsNullOrEmpty(finalDest)) return;

                            long size = 0;
                            try { size = Convert.ToInt64(sizeStr); } catch { }

                            if (!finalDest.StartsWith("127.") && !finalDest.StartsWith("224.") && !finalDest.StartsWith("::1") && finalDest != "255.255.255.255") {
                                if (size > 0 || evName.Contains("Connect") || isDnsEvent) {
                                    var evt = new FfiPlatformEvent {
                                        timestamp = DateTime.Now.ToString("O"),
                                        user = GetProcessUser(data.ProcessID),
                                        process = procName,
                                        filepath = "Network_Socket",
                                        destination = finalDest,
                                        bytes = size > 0 ? size : 1,
                                        duration_ms = 1
                                    };

                                    if (!_uebaQueue.IsAddingCompleted) {
                                        _uebaQueue.TryAdd(evt, 0);
                                        if (_enableUniversalLedger) { _uebaJsonQueue.TryAdd(evt, 0); }
                                    }
                                }
                            }
                        }

                    } catch (Exception ex) {
                        try { EventQueue.Enqueue(new DataEvent { EventType = "ERROR", RawJson = "Hotpath Error: " + ex.Message }); } catch {}
                    }
                };
                _session.Source.Process();
            } catch (Exception ex) {
                EventQueue.Enqueue(new DataEvent { EventType = "FATAL", RawJson = "ETW Core Failure: " + ex.Message });
            }
        });
    }

    public static void RecoverSession() {
        if (_session != null) {
            try { _session.Stop(); _session.Dispose(); } catch { }
        }
        StartSession();
    }

    public static void StopSession() {
        _uebaQueue.CompleteAdding();
        _uebaJsonQueue.CompleteAdding();
        _cts.Cancel();

        if (_session != null) {
            _session.Stop();
            _session.Dispose();
        }

        if (_mlEnginePtr != IntPtr.Zero) {
            teardown_engine(_mlEnginePtr);
            _mlEnginePtr = IntPtr.Zero;
            EventQueue.Enqueue(new DataEvent { EventType = "DiagLog", RawJson = "Native Rust DLL safely unloaded and FFI pointers freed." });
        }
    }
}