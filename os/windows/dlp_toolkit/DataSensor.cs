/*=============================================================================================
 * SYSTEM:          Data Sensor
 * COMPONENT:       DataSensor.cs (Unmanaged ETW Listener & Active Defense)
 * AUTHOR:          Robert Weber
 * DESCRIPTION:
 * High-performance ETW engine monitoring Network volumetric flow & Process Lineage.
 * Deep File Inspection is now delegated to the in-band Ring-3 Rust Interceptor via IPC.
 *============================================================================================*/

using System;
using System.IO;
using System.IO.Pipes;
using System.Linq;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO.Compression;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using System.Threading.Tasks;
using System.Threading;
using Microsoft.Diagnostics.Tracing;
using Microsoft.Diagnostics.Tracing.Session;

public class RealTimeDataSensor {

    [DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    static extern bool SetDllDirectory(string lpPathName);

    // --- NATIVE RUST FFI BOUNDARIES (ML ENGINE) ---
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
    private static extern void free_string(IntPtr s);

    [DllImport("DataSensor_ML.dll", CallingConvention = CallingConvention.Cdecl)]
    private static extern void teardown_engine(IntPtr engine);

    [DllImport("DataSensor_ML.dll", CallingConvention = CallingConvention.Cdecl)]
    private static extern IntPtr scan_text_payload(IntPtr engine, string text, string process, string user);

    [DllImport("DataSensor_ML.dll", CallingConvention = CallingConvention.Cdecl)]
    private static extern int groom_database(IntPtr engine, uint days_to_keep);

    public static int TriggerGrooming(uint days) {
        if (_mlEnginePtr != IntPtr.Zero) {
            return groom_database(_mlEnginePtr, days);
        }
        return -1;
    }

    // --- PROCESS CACHE & INJECTION P/INVOKES ---
    private static ConcurrentDictionary<int, string> _pidUserCache = new ConcurrentDictionary<int, string>();

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, int dwProcessId);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    static extern bool OpenProcessToken(IntPtr ProcessHandle, uint DesiredAccess, out IntPtr TokenHandle);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    static extern bool CloseHandle(IntPtr hObject);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, uint nSize, out UIntPtr lpNumberOfBytesWritten);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);

    [DllImport("kernel32.dll", CharSet = CharSet.Ansi, ExactSpelling = true, SetLastError = true)]
    static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

    [DllImport("kernel32.dll", CharSet = CharSet.Auto)]
    public static extern IntPtr GetModuleHandle(string lpModuleName);
    [DllImport("kernel32.dll", SetLastError = true, CallingConvention = CallingConvention.Winapi)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool IsWow64Process([In] IntPtr process, [Out] out bool wow64Process);

    // --- CLIPBOARD P/INVOKES ---
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

    // --- STATE MANAGEMENT ---
    private static BlockingCollection<FfiPlatformEvent> _uebaQueue = new BlockingCollection<FfiPlatformEvent>(100000);
    private static BlockingCollection<FfiPlatformEvent> _uebaJsonQueue = new BlockingCollection<FfiPlatformEvent>(100000);
    private static Thread _clipboardWorker;
    private static Thread _uebaJsonWorker;
    private static ConcurrentDictionary<string, string> _volumeMap = new ConcurrentDictionary<string, string>(StringComparer.OrdinalIgnoreCase);

    public class DataEvent {
        public string EventType;
        public string ProcessName;
        public string UserName;
        public string RawJson;
    }

    public static ConcurrentQueue<DataEvent> EventQueue = new ConcurrentQueue<DataEvent>();
    public static int _eventQueueCount = 0;
    private static HashSet<string> _trustedProcesses = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
    private static IntPtr _mlEnginePtr = IntPtr.Zero;
    private static TraceEventSession _session;
    private static CancellationTokenSource _cts = new CancellationTokenSource();
    private static bool _enableUniversalLedger = false;
    private static string _hookDllPath = @"C:\ProgramData\DataSensor\Bin\DataSensor_Hook.dll";

    // --- WIN32 ACCESS RIGHT CONSTANTS ---
    private const uint PROCESS_QUERY_LIMITED_INFORMATION = 0x1000;
    private const uint PROCESS_CREATE_THREAD             = 0x0002;
    private const uint PROCESS_QUERY_INFORMATION         = 0x0400;
    private const uint PROCESS_VM_OPERATION              = 0x0008;
    private const uint PROCESS_VM_WRITE                  = 0x0020;
    private const uint PROCESS_VM_READ                   = 0x0010;
    private const uint INJECT_ACCESS = PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION
                                    | PROCESS_VM_OPERATION  | PROCESS_VM_WRITE | PROCESS_VM_READ;

    private static string JsonEscape(string s) {
        if (s == null) return "";
        return s.Replace("\0", "")
                .Replace("\\", "\\\\")
                .Replace("\"", "\\\"")
                .Replace("\n",  "\\n")
                .Replace("\r",  "\\r")
                .Replace("\t",  "\\t")
                .Replace("\b",  "\\b")
                .Replace("\f",  "\\f");
    }

    public static void InitializeEngine(string configJson, long maxMb, string trustedProcsCsv, bool enableLedger) {
        _enableUniversalLedger = enableLedger;

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
                StartNamedPipeListener();
                StartBatchProcessor();
                StartClipboardMonitor();
                if (_enableUniversalLedger) { StartUebaJsonLogger(); }
            } else {
                EventQueue.Enqueue(new DataEvent { EventType = "FATAL", RawJson = "Native FFI Pointer returned null." });
            }
        } catch (Exception ex) {
            EventQueue.Enqueue(new DataEvent { EventType = "FATAL", RawJson = ex.Message });
        }
    }

    public static void InjectExistingProcesses() {
        Task.Run(() => {
            foreach (var proc in System.Diagnostics.Process.GetProcesses()) {
                try {
                    if (proc.Id <= 4) continue;
                    if (_trustedProcesses.Contains(proc.ProcessName)) continue;
                    IntPtr hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, proc.Id);
                    if (hProc != IntPtr.Zero) {
                        IsWow64Process(hProc, out bool is32Bit);
                        CloseHandle(hProc);
                        if (!is32Bit) { InjectRustHook(proc.Id); }
                    }
                } catch { }
            }
            EventQueue.Enqueue(new DataEvent { EventType = "DiagLog", RawJson = "Retroactive Ring-3 Hooks deployed to running processes." });
        });
    }

    private static string GetProcessUser(int pid) {
        if (pid <= 4) return "System";
        if (_pidUserCache.TryGetValue(pid, out string cachedUser)) return cachedUser;

        string userName = "System";
        IntPtr processHandle = IntPtr.Zero;
        IntPtr tokenHandle = IntPtr.Zero;

        try {
            processHandle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid);
            if (processHandle != IntPtr.Zero) {
                if (OpenProcessToken(processHandle, 0x0008, out tokenHandle)) {
                    using (WindowsIdentity wi = new WindowsIdentity(tokenHandle)) {
                        userName = wi.Name;
                        if (userName.Contains("\\")) { userName = userName.Split('\\')[1]; }
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
                return kvp.Value + ntPath.Substring(kvp.Key.Length);
            }
        }
        return ntPath;
    }

    // --- RUST DLL INJECTION & IPC ---
    public static void InjectRustHook(int targetPid) {
        if (!File.Exists(_hookDllPath)) return;

        IntPtr hProcess = OpenProcess(INJECT_ACCESS, false, targetPid);
        if (hProcess == IntPtr.Zero) return;

        try {
            byte[] pathBytes = Encoding.Unicode.GetBytes(_hookDllPath + "\0");
            uint size = (uint)pathBytes.Length;

            IntPtr allocMemAddress = VirtualAllocEx(hProcess, IntPtr.Zero, size, 0x3000, 0x04); // 0x04 = PAGE_READWRITE

            WriteProcessMemory(hProcess, allocMemAddress, pathBytes, size, out _);
            IntPtr loadLibraryAddr = GetProcAddress(GetModuleHandle("kernel32.dll"), "LoadLibraryW");

            CreateRemoteThread(hProcess, IntPtr.Zero, 0, loadLibraryAddr, allocMemAddress, 0, IntPtr.Zero);
        } finally {
            CloseHandle(hProcess);
        }
    }

    private static NamedPipeServerStream CreateSecurePipeServer() {
        var security = new PipeSecurity();
        security.AddAccessRule(new PipeAccessRule(
            new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null),
            PipeAccessRights.ReadWrite,
            AccessControlType.Allow));
        security.AddAccessRule(new PipeAccessRule(
            new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null),
            PipeAccessRights.ReadWrite,
            AccessControlType.Allow));

    #if NETFRAMEWORK
        return new NamedPipeServerStream(
            "DataSensorAlerts",
            PipeDirection.In,
            NamedPipeServerStream.MaxAllowedServerInstances,
            PipeTransmissionMode.Byte,
            PipeOptions.Asynchronous,
            0,
            0,
            security);
    #else
        return NamedPipeServerStreamAcl.Create(
            "DataSensorAlerts",
            PipeDirection.In,
            NamedPipeServerStream.MaxAllowedServerInstances,
            PipeTransmissionMode.Byte,
            PipeOptions.Asynchronous,
            0,
            0,
            security);
    #endif
    }

    private static void StartNamedPipeListener() {
        Task.Run(async () => {
            while (!_cts.Token.IsCancellationRequested) {
                try {
                    var pipeServer = CreateSecurePipeServer();
                    try { await pipeServer.WaitForConnectionAsync(_cts.Token); } catch { pipeServer.Dispose(); break; }

                    _ = Task.Run(() => {
                        try {
                            using (var reader = new StreamReader(pipeServer)) {
                                string alertJson = reader.ReadToEnd();
                                if (!string.IsNullOrWhiteSpace(alertJson)) {

                                    // --- DEEP ARCHIVE DELEGATION (NATIVE HOOK REVIEW) ---
                                    if (alertJson.Contains("ASYNC_INSPECT_QUEUED")) {
                                        EventQueue.Enqueue(new DataEvent {
                                        EventType = "DLP_ALERT",
                                        ProcessName = "In-Band Hook",
                                        UserName = "System",
                                        RawJson = "{\"alerts\":[" + alertJson + "]}"
                                    });

                                        string zipPath = alertJson.Split(new[] { "\"filepath\":\"" }, StringSplitOptions.None)[1].Split('"')[0];
                                        Task.Run(() => {
                                            try {
                                                Thread.Sleep(1500); // Allow Compress-Archive lock to release
                                                string tempDir = @"C:\ProgramData\DataSensor\TempArchive\" + Guid.NewGuid().ToString();
                                                Directory.CreateDirectory(tempDir);

                                                // NATIVE INTERCEPT: The hook catches the extraction stream!
                                                System.IO.Compression.ZipFile.ExtractToDirectory(zipPath, tempDir);

                                                Thread.Sleep(1000); // Allow hook to finish processing buffers
                                                Directory.Delete(tempDir, true);
                                                File.Delete(zipPath);
                                            } catch (Exception ex) {
                                                EventQueue.Enqueue(new DataEvent { EventType = "ERROR", RawJson = "Archive Extraction Failed: " + ex.Message });
                                            }
                                        });
                                    }
                                    else {
                                        EventQueue.Enqueue(new DataEvent {
                                            EventType = "DLP_ALERT",
                                            ProcessName = "In-Band Hook",
                                            UserName = "System",
                                            RawJson = "{\"alerts\":[" + alertJson + "]}"
                                        });
                                        try {
                                            string evtFilePath = "Unknown";
                                            var fpParts = alertJson.Split(new[] { "\"filepath\":\"" }, StringSplitOptions.None);
                                            if (fpParts.Length > 1) {
                                                evtFilePath = fpParts[1].Split('"')[0].Replace("\\\\", "\\");
                                            }
                                            long evtBytes = 0;
                                            try {
                                                if (File.Exists(evtFilePath))
                                                    evtBytes = new FileInfo(evtFilePath).Length;
                                            } catch { }
                                            var hookEvt = new FfiPlatformEvent {
                                                timestamp   = DateTime.Now.ToString("O"),
                                                user        = "HookEngine",
                                                process     = "In-Band Hook",
                                                filepath    = evtFilePath,
                                                destination = "Disk_Write",
                                                bytes       = evtBytes,
                                                duration_ms = 1
                                            };
                                            if (!_uebaQueue.IsAddingCompleted) {
                                                _uebaQueue.TryAdd(hookEvt, 0);
                                            }
                                        } catch { }
                                    }
                                }
                            }
                        } catch { } finally { if (pipeServer != null) { pipeServer.Dispose(); } }
                    });
                } catch { Thread.Sleep(100); }
            }
        });
    }

    // --- NETWORK HELPERS ---
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

    // --- WORKER THREADS ---
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
                                string safePath = JsonEscape(e.filepath);
                                string safeDest = JsonEscape(e.destination);
                                sb.Append($"{{\"timestamp\":\"{JsonEscape(e.timestamp)}\",\"user\":\"{JsonEscape(e.user)}\",\"process\":\"{JsonEscape(e.process)}\",\"filepath\":\"{safePath}\",\"destination\":\"{safeDest}\",\"bytes\":{e.bytes},\"duration_ms\":{e.duration_ms}}}");
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
                                string currentText = null;
                                try {
                                    currentText = Marshal.PtrToStringUni(pData);
                                } finally {
                                    GlobalUnlock(hData);
                                }

                                if (!string.IsNullOrEmpty(currentText) && currentText != lastClipboardText) {
                                    lastClipboardText = currentText;

                                    string activeProcessName = "Unknown_App";
                                    try {
                                        IntPtr hWnd = GetClipboardOwner();
                                        if (hWnd == IntPtr.Zero) hWnd = GetForegroundWindow();
                                        if (hWnd != IntPtr.Zero) {
                                            GetWindowThreadProcessId(hWnd, out uint pid);
                                            using (var proc = System.Diagnostics.Process.GetProcessById((int)pid)) {
                                                activeProcessName = proc.ProcessName;
                                            }
                                        }
                                    } catch { }

                                    var evt = new FfiPlatformEvent {
                                        timestamp = DateTime.Now.ToString("O"),
                                        user = Environment.UserName,
                                        process = activeProcessName,
                                        filepath = "Clipboard_Capture",
                                        destination = "Memory_Buffer",
                                        bytes = currentText.Length * 2,
                                        duration_ms = 1
                                    };

                                    if (_mlEnginePtr != IntPtr.Zero) {
                                        IntPtr alertPtr = scan_text_payload(_mlEnginePtr, currentText, activeProcessName, Environment.UserName);
                                        ParseResponse(alertPtr, activeProcessName, Environment.UserName, 0, "DLP_ALERT");
                                    }

                                    if (!_uebaQueue.IsAddingCompleted) {
                                        _uebaQueue.TryAdd(evt, 0);
                                        if (_enableUniversalLedger) { _uebaJsonQueue.TryAdd(evt, 0); }
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
            using (FileStream fs = new FileStream(logPath, FileMode.Append, FileAccess.Write, FileShare.ReadWrite, 65536))
            using (StreamWriter sw = new StreamWriter(fs) { AutoFlush = false }) {
                while (!_cts.Token.IsCancellationRequested || _uebaJsonQueue.Count > 0) {
                    try {
                        foreach (var evt in _uebaJsonQueue.GetConsumingEnumerable(_cts.Token)) {
                            string safePath = evt.filepath != null ? JsonEscape(evt.filepath) : "";
                            string safeDest = evt.destination != null ? JsonEscape(evt.destination) : "";
                            string jsonLine = $"{{\"Timestamp\":\"{JsonEscape(evt.timestamp)}\", \"User\":\"{JsonEscape(evt.user)}\", \"Process\":\"{JsonEscape(evt.process)}\", \"FilePath\":\"{safePath}\", \"Destination\":\"{safeDest}\", \"Bytes\":{evt.bytes}, \"DurationMs\":{evt.duration_ms}}}";
                            sw.WriteLine(jsonLine);
                        }
                        sw.Flush();
                    } catch (OperationCanceledException) { break; }
                    catch { Thread.Sleep(500); }
                }
            }
        });
        _uebaJsonWorker.IsBackground = true;
        _uebaJsonWorker.Start();
    }

    private static void ParseResponse(IntPtr resultPtr, string processName, string userName, uint threadId, string defaultAlertType) {
        if (resultPtr != IntPtr.Zero) {
            string resultJson = Marshal.PtrToStringAnsi(resultPtr);
            free_string(resultPtr);

            if (resultJson != null) {
                if (resultJson.Contains("alert_type") && _eventQueueCount < 5000) {
                    EventQueue.Enqueue(new DataEvent {
                        EventType = defaultAlertType,
                        ProcessName = processName,
                        UserName = userName,
                        RawJson = resultJson
                    });
                    Interlocked.Increment(ref _eventQueueCount);
                }
                else if (resultJson.Contains("daemon_error") && !resultJson.Contains("\"daemon_error\":null")) {
                    EventQueue.Enqueue(new DataEvent {
                        EventType = "FATAL",
                        RawJson = "Native Engine Fault: " + resultJson
                    });
                }
            }
        }
    }

    // --- CORE ETW SESSION ---
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

                _session.Source.Dynamic.All += delegate (TraceEvent data) {
                    try {
                        string evName = data.EventName;
                        if (evName == "ThreadWorkOnBehalfUpdate" || evName == "CpuPriorityChange" || evName.StartsWith("Thread") || evName == "ImageLoad" || evName == "ImageUnload") return;

                        // 1. Process Lineage Pre-Caching & DLL INJECTION
                        if (data.ProviderName.Contains("Kernel-Process") && evName.Contains("Start")) {
                            Task.Run(() => {
                                try {
                                    string userName = "System";
                                    IntPtr processHandle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, data.ProcessID);
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

                                    string procName = string.IsNullOrEmpty(data.ProcessName) ? data.ProcessID.ToString() : data.ProcessName;
                                    if (!_trustedProcesses.Contains(procName)) {
                                        Task.Run(async () => {
                                            await Task.Delay(250);
                                            IntPtr hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, data.ProcessID);
                                            if (hProc != IntPtr.Zero) {
                                                IsWow64Process(hProc, out bool is32Bit);
                                                CloseHandle(hProc);
                                                if (!is32Bit) { // Only inject 64-bit DLL into 64-bit processes
                                                    InjectRustHook(data.ProcessID);
                                                }
                                            }
                                        });
                                    }
                                } catch { }
                            });
                        }
                        if (_pidUserCache.Count > 5000) {
                            _pidUserCache.Clear();
                        }

                        string procName = string.IsNullOrEmpty(data.ProcessName) ? data.ProcessID.ToString() : data.ProcessName;
                        if (_trustedProcesses.Contains(procName)) return;

                        // 2. Network & DNS Routing
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
                                    string fbIp = FallbackIpExtract(rawPayload, out _);
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
        if (_session != null) {
            _session.Stop();
            _session.Dispose();
            _session = null;
        }

        _cts.Cancel();
        _uebaQueue.CompleteAdding();
        _uebaJsonQueue.CompleteAdding();

        Thread.Sleep(500);

        if (_mlEnginePtr != IntPtr.Zero) {
            teardown_engine(_mlEnginePtr);
            _mlEnginePtr = IntPtr.Zero;
            EventQueue.Enqueue(new DataEvent { EventType = "DiagLog", RawJson = "Native Rust DLL safely unloaded and FFI pointers freed." });
        }
    }
}