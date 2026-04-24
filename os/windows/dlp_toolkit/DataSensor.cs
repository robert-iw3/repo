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
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Threading.Tasks;
using System.Threading;
using System.Runtime.InteropServices;
using Microsoft.Diagnostics.Tracing;
using Microsoft.Diagnostics.Tracing.Session;

public class RealTimeDataSensor {

    // --- WIN32 API MITIGATION HOOKS ---
    [DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    static extern bool SetDllDirectory(string lpPathName);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern IntPtr OpenThread(int dwDesiredAccess, bool bInheritHandle, uint dwThreadId);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern uint SuspendThread(IntPtr hThread);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool CloseHandle(IntPtr hObject);

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
    private static extern IntPtr process_telemetry_batch(IntPtr engine, [In] FfiPlatformEvent[] events, UIntPtr event_count);

    [DllImport("DataSensor_ML.dll", CallingConvention = CallingConvention.Cdecl)]
    private static extern IntPtr inspect_file_content(IntPtr engine, string file_ext, byte[] buffer, UIntPtr buffer_len);

    [DllImport("DataSensor_ML.dll", CallingConvention = CallingConvention.Cdecl)]
    private static extern void free_string(IntPtr s);

    [DllImport("DataSensor_ML.dll", CallingConvention = CallingConvention.Cdecl)]
    private static extern void teardown_engine(IntPtr engine);

    public class DataEvent {
        public string EventType { get; set; }
        public string ProcessName { get; set; }
        public string RawJson { get; set; }
    }

    public static ConcurrentQueue<DataEvent> EventQueue = new ConcurrentQueue<DataEvent>();
    private static BlockingCollection<FfiPlatformEvent> _uebaQueue = new BlockingCollection<FfiPlatformEvent>(100000);
    private static HashSet<string> _trustedProcesses = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
    private static IntPtr _mlEnginePtr = IntPtr.Zero;
    private static TraceEventSession _session;
    private static CancellationTokenSource _cts = new CancellationTokenSource();
    private static long _maxInspectionBytes = 150 * 1024 * 1024;

    public static void InitializeEngine(string configJson, long maxMb, string trustedProcsCsv) {
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
                StartBatchProcessor();
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
            try {
                foreach (var item in _uebaQueue.GetConsumingEnumerable(_cts.Token)) {
                    batch.Add(item);

                    while (batch.Count < 5000 && _uebaQueue.TryTake(out FfiPlatformEvent nextItem)) {
                        batch.Add(nextItem);
                    }

                    if (batch.Count > 0 && _mlEnginePtr != IntPtr.Zero) {
                        FfiPlatformEvent[] eventArray = batch.ToArray();
                        IntPtr resultPtr = process_telemetry_batch(_mlEnginePtr, eventArray, new UIntPtr((uint)eventArray.Length));
                        ParseResponse(resultPtr, "UEBA_Engine", 0, "UEBA_ALERT");
                        batch.Clear();
                    }
                }
            }
            catch (OperationCanceledException) { /* Clean teardown */ }
        });
    }

    public static void StartSession() {
        Task.Run(() => {
            try {
                if (TraceEventSession.GetActiveSessionNames().Contains("DataSensorSession")) {
                    new TraceEventSession("DataSensorSession").Dispose();
                }

                _session = new TraceEventSession("DataSensorSession");
                _session.EnableProvider("Microsoft-Windows-Kernel-File");
                _session.EnableProvider("Microsoft-Windows-Kernel-Network");

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
                                user = "System",
                                process = procName,
                                filepath = fileName,
                                destination = "Disk_Write",
                                bytes = byteCount,
                                duration_ms = 10
                            };

                            if (!_uebaQueue.IsAddingCompleted) {
                                _uebaQueue.TryAdd(evt, 0);
                            }

                            if (fileName.StartsWith(@"\device\harddiskvolume") && byteCount > 4096) {
                                Task.Run(() => ScanFileContent(fileName, procName, threadId));
                            }
                        }
                    }
                    else if (data.EventName == "TcpIp/Send" || data.EventName == "UdpIp/Send") {
                        long byteCount = Convert.ToInt64(data.PayloadByName("size") ?? 0);
                        string destIp = (data.PayloadStringByName("daddr") ?? "UnknownIP");

                        if (byteCount > 0 && destIp != "UnknownIP") {
                            var evt = new FfiPlatformEvent {
                                timestamp = data.TimeStamp.ToString("O"),
                                user = "System",
                                process = procName,
                                filepath = "Network_Socket",
                                destination = destIp,
                                bytes = byteCount,
                                duration_ms = 1
                            };

                            if (!_uebaQueue.IsAddingCompleted) {
                                _uebaQueue.TryAdd(evt, 0);
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

    private static void ScanFileContent(string rawDevicePath, string processName, uint threadId) {
        if (_mlEnginePtr == IntPtr.Zero) return;

        try {
            string dosPath = rawDevicePath.Replace(@"\device\", @"C:\");
            if (!File.Exists(dosPath)) return;

            FileInfo fi = new FileInfo(dosPath);
            if (fi.Length > _maxInspectionBytes || fi.Length == 0) return;

            string ext = fi.Extension.ToLower();

            using (FileStream fs = new FileStream(dosPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete)) {
                long readLength = Math.Min(fs.Length, 10 * 1024 * 1024);
                byte[] buffer = new byte[readLength];
                int bytesRead = fs.Read(buffer, 0, buffer.Length);

                if (bytesRead > 0) {
                    IntPtr resultPtr = inspect_file_content(_mlEnginePtr, ext, buffer, new UIntPtr((uint)bytesRead));
                    ParseResponse(resultPtr, processName, threadId, "DLP_ALERT");
                }
            }

        } catch { /* Suppress read locks on protected active streams */ }
    }

    private static void ParseResponse(IntPtr resultPtr, string processName, uint threadId, string defaultAlertType) {
        if (resultPtr != IntPtr.Zero) {
            string resultJson = Marshal.PtrToStringAnsi(resultPtr);
            free_string(resultPtr);

            if (resultJson != null && resultJson.Contains("alert_type")) {
                EventQueue.Enqueue(new DataEvent {
                    EventType = defaultAlertType,
                    ProcessName = processName,
                    RawJson = resultJson
                });

                // Trigger Active Defense if Native Engine mandates mitigation
                if (resultJson.Contains("SUSPEND_THREAD") && threadId != 0) {
                    MitigateThreat(threadId, processName);
                }
            }
        }
    }

    private static void MitigateThreat(uint threadId, string processName) {
        // THREAD_SUSPEND_RESUME access right (0x0002)
        IntPtr hThread = OpenThread(0x0002, false, threadId);
        if (hThread != IntPtr.Zero) {
            SuspendThread(hThread);
            CloseHandle(hThread);

            EventQueue.Enqueue(new DataEvent {
                EventType = "MITIGATION",
                RawJson = $"Thread ID {threadId} attached to {processName} has been suspended. Data flow mitigated."
            });
        }
    }

    public static void StopSession() {
        _uebaQueue.CompleteAdding();
        _cts.Cancel();

        if (_session != null) {
            _session.Stop();
            _session.Dispose();
        }

        if (_mlEnginePtr != IntPtr.Zero) {
            teardown_engine(_mlEnginePtr);
            _mlEnginePtr = IntPtr.Zero;
        }
    }
}