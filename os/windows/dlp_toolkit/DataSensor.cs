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
using System.Threading.Tasks;
using System.Threading;
using System.Runtime.InteropServices;
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
    static extern uint EnumClipboardFormats(uint format);

    [DllImport("user32.dll")]
    static extern IntPtr GetForegroundWindow();

    [DllImport("user32.dll", SetLastError = true)]
    static extern uint GetWindowThreadProcessId(IntPtr hWnd, out uint lpdwProcessId);

    [DllImport("kernel32.dll")]
    static extern IntPtr GlobalLock(IntPtr hMem);

    [DllImport("kernel32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    static extern bool GlobalUnlock(IntPtr hMem);

    public class DataEvent {
        public string EventType { get; set; }
        public string ProcessName { get; set; }
        public string RawJson { get; set; }
    }

    public static ConcurrentQueue<DataEvent> EventQueue = new ConcurrentQueue<DataEvent>();
    private static BlockingCollection<Tuple<string, string, string>> _deepInspectionQueue = new BlockingCollection<Tuple<string, string, string>>(1000);
    private static Thread _inspectionWorker;
    private static HashSet<string> _trustedProcesses = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
    private static IntPtr _mlEnginePtr = IntPtr.Zero;
    private static TraceEventSession _session;
    private static CancellationTokenSource _cts = new CancellationTokenSource();
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
                            ParseResponse(resultPtr, "UEBA_Engine", 0, "UEBA_ALERT");
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
                        uint format = 13; // CF_UNICODETEXT
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
                                        IntPtr hWnd = GetForegroundWindow();
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
                                        timestamp = DateTime.UtcNow.ToString("O"),
                                        user = Environment.UserName,
                                        process = activeProcessName,
                                        filepath = "Clipboard_Capture",
                                        destination = "Memory_Buffer",
                                        bytes = currentText.Length * 2, // UTF-16 byte estimation
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
                } catch {
                }
                Thread.Sleep(1000); // Polling interval to prevent CPU spike
            }
        });
        _clipboardWorker.SetApartmentState(ApartmentState.STA); // Required for OLE/Clipboard operations
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
                    Thread.Sleep(500); // Suppress transient OS locks
                }
            }
        });
        _uebaJsonWorker.IsBackground = true;
        _uebaJsonWorker.Start();
    }

    public static void StartSession() {
        Task.Run(() => {
            try {
                if (TraceEventSession.GetActiveSessionNames().Contains("DataSensorSession")) {
                    new TraceEventSession("DataSensorSession").Dispose();
                }

                _session = new TraceEventSession("DataSensorSession");

                _session.EnableKernelProvider(
                    Microsoft.Diagnostics.Tracing.Parsers.KernelTraceEventParser.Keywords.FileIO |
                    Microsoft.Diagnostics.Tracing.Parsers.KernelTraceEventParser.Keywords.NetworkTCPIP
                );

                _session.Source.Dynamic.All += delegate (TraceEvent data) {
                    string procName = string.IsNullOrEmpty(data.ProcessName) ? data.ProcessID.ToString() : data.ProcessName;

                    if (_trustedProcesses.Contains(procName)) return;
                    uint threadId = (uint)data.ThreadID;

                    if (data.EventName == "Write") {
                        long byteCount = Convert.ToInt64(data.PayloadByName("IoSize") ?? 0);
                        string fileName = (data.PayloadStringByName("FileName") ?? "").ToLowerInvariant();

                        if (byteCount > 0 && !string.IsNullOrEmpty(fileName)) {
                            var evt = new FfiPlatformEvent {
                                timestamp = data.TimeStamp.ToString("O"),
                                user = Environment.UserName,
                                process = procName,
                                filepath = fileName,
                                destination = "Disk_Write",
                                bytes = byteCount,
                                duration_ms = 10
                            };

                            if (!_uebaQueue.IsAddingCompleted) {
                                _uebaQueue.TryAdd(evt, 0);
                                _uebaJsonQueue.TryAdd(evt, 0);
                            }

                            if (fileName.StartsWith(@"\device\harddiskvolume") && byteCount > 0) {
                                string dosPath = System.Text.RegularExpressions.Regex.Replace(
                                    fileName,
                                    @"^\\device\\harddiskvolume\d+\\",
                                    @"C:\",
                                    System.Text.RegularExpressions.RegexOptions.IgnoreCase
                                );

                                if (!_deepInspectionQueue.IsAddingCompleted) {
                                    _deepInspectionQueue.Add(new Tuple<string, string, string>(dosPath, procName, Environment.UserName));
                                }
                            }
                        }
                    }
                    else if (data.EventName == "TcpIp/Send" || data.EventName == "UdpIp/Send") {
                        long byteCount = Convert.ToInt64(data.PayloadByName("size") ?? 0);
                        string destIp = (data.PayloadStringByName("daddr") ?? "UnknownIP");

                        if (byteCount > 0 && destIp != "UnknownIP" && !destIp.StartsWith("127.") && destIp != "255.255.255.255") {
                            var evt = new FfiPlatformEvent {
                                timestamp = data.TimeStamp.ToString("O"),
                                user = Environment.UserName,
                                process = procName,
                                filepath = "Network_Socket",
                                destination = destIp,
                                bytes = byteCount,
                                duration_ms = 1
                            };

                            if (!_uebaQueue.IsAddingCompleted) {
                                _uebaQueue.TryAdd(evt, 0);
                                _uebaJsonQueue.TryAdd(evt, 0);
                            }
                        }
                    }
                };
                _session.Source.Process();
            } catch (Exception ex) {
                EventQueue.Enqueue(new DataEvent { EventType = "FATAL", RawJson = ex.Message });
            }
        });
    }

    private static SemaphoreSlim _ioSemaphore = new SemaphoreSlim(2, 2);

    private static void ScanFileContent(string rawDevicePath, string processName, uint threadId) {
        if (_mlEnginePtr == IntPtr.Zero) return;

        if (!_ioSemaphore.Wait(0)) return;

        try {
            string dosPath = rawDevicePath.Replace(@"\device\", @"C:\");
            if (!File.Exists(dosPath)) return;

            FileInfo fi = new FileInfo(dosPath);
            if (fi.Length > _maxInspectionBytes || fi.Length == 0) return;

            string ext = string.IsNullOrEmpty(fi.Extension) ? "" : fi.Extension.ToLowerInvariant();

            IntPtr resultPtr = inspect_file_content(_mlEnginePtr, ext, dosPath, "Deep_Inspector", Environment.UserName);
            ParseResponse(resultPtr, processName, threadId, "DLP_ALERT");

        } catch {
        } finally {
            _ioSemaphore.Release();
        }
    }

    private static void StartDeepInspectionWorker() {
        _inspectionWorker = new Thread(() => {
            foreach (var item in _deepInspectionQueue.GetConsumingEnumerable(_cts.Token)) {
                if (_mlEnginePtr == IntPtr.Zero) continue;
                try {
                    Thread.Sleep(300);

                    FileInfo fi = new FileInfo(item.Item1);
                    if (fi.Length > _maxInspectionBytes || fi.Length == 0) continue;

                    string ext = string.IsNullOrEmpty(fi.Extension) ? "" : fi.Extension.ToLowerInvariant();
                    IntPtr resultPtr = inspect_file_content(_mlEnginePtr, ext, item.Item1, item.Item2, item.Item3);
                    ParseResponse(resultPtr, item.Item2, 0, "DLP_ALERT");
                } catch { /* Suppress transient I/O locks */ }
            }
        });
        _inspectionWorker.IsBackground = true;
        _inspectionWorker.Start();
    }

    private static void ParseResponse(IntPtr resultPtr, string processName, uint threadId, string defaultAlertType) {
        if (resultPtr != IntPtr.Zero) {
            string resultJson = Marshal.PtrToStringAnsi(resultPtr);
            free_string(resultPtr);

            if (resultJson != null && resultJson.Contains("alert_type")) {
                if (EventQueue.Count < 5000) {
                    EventQueue.Enqueue(new DataEvent {
                        EventType = defaultAlertType,
                        ProcessName = processName,
                        RawJson = resultJson
                    });
                }
            }
        }
    }

    public static void RecoverSession() {
        if (_session != null) {
            try {
                _session.Stop();
                _session.Dispose();
            } catch { /* Suppress disposal race conditions */ }
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