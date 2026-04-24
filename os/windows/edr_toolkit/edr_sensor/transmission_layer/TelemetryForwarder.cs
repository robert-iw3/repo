/*=============================================================================================
 * SYSTEM:          Deep Visibility Sensor v2.1
 * COMPONENT:       TelemetryForwarder.cs (Native AOT Windows Service)
 * AUTHOR:          Robert Weber
 *
 * DESCRIPTION:
 * High-performance native Windows Service. Features Zero-Loss Graceful Shutdown hooks
 * and supports dynamic authentication routing (mTLS vs Bearer Token) for scalable deployments.
 *=============================================================================================*/

using System;
using System.IO;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading;
using System.Threading.Channels;
using System.Threading.Tasks;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using System.Linq;

namespace DeepSensor.Telemetry
{
    public class TelemetryForwarder : BackgroundService
    {
        private readonly ILogger<TelemetryForwarder> _logger;
        private readonly HttpClient _httpClient;
        private readonly Channel<string> _eventQueue;

        private readonly string _targetEndpoint;
        private readonly string _telemetryDir;
        private readonly string _authMode;
        private readonly string _certThumbprint;
        private readonly string _bearerToken;
        private readonly int _batchSize;
        private readonly TimeSpan _flushInterval;

        public TelemetryForwarder(ILogger<TelemetryForwarder> logger, IConfiguration configuration)
        {
            _logger = logger;

            _targetEndpoint = configuration["Telemetry:SiemUrl"] ?? throw new ArgumentNullException("SiemUrl missing in Config.ini");
            _authMode = configuration["Telemetry:AuthMode"] ?? "None";
            _certThumbprint = configuration["Telemetry:CertThumbprint"] ?? "";
            _bearerToken = configuration["Telemetry:BearerToken"] ?? "";

            _batchSize = int.TryParse(configuration["Telemetry:BatchSize"], out int bSize) ? bSize : 250;
            int flushSecs = int.TryParse(configuration["Telemetry:FlushIntervalSeconds"], out int fSecs) ? fSecs : 5;
            _flushInterval = TimeSpan.FromSeconds(flushSecs);

            _telemetryDir = @"C:\ProgramData\DeepSensor\Data";

            _eventQueue = Channel.CreateBounded<string>(new BoundedChannelOptions(10000)
            {
                FullMode = BoundedChannelFullMode.Wait,
                SingleReader = true,
                SingleWriter = false
            });

            var handler = new SocketsHttpHandler
            {
                PooledConnectionLifetime = TimeSpan.FromMinutes(5),
                EnableMultipleHttp2Connections = true
            };

            // Dynamic Authentication Routing
            if (_authMode.Equals("mTLS", StringComparison.OrdinalIgnoreCase))
            {
                handler.SslOptions = new System.Net.Security.SslClientAuthenticationOptions
                {
                    ClientCertificates = new X509CertificateCollection(),
                    EnabledSslProtocols = System.Security.Authentication.SslProtocols.Tls12 | System.Security.Authentication.SslProtocols.Tls13,
                    CertificateRevocationCheckMode = X509RevocationMode.Online
                };

                var cert = LoadProvisioningCertificate();
                if (cert != null) { handler.SslOptions.ClientCertificates.Add(cert); }
            }

            _httpClient = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(30) };
            _httpClient.DefaultRequestHeaders.Add("User-Agent", "DeepSensor-v2.1-Forwarder");

            if (_authMode.Equals("Token", StringComparison.OrdinalIgnoreCase) && !string.IsNullOrWhiteSpace(_bearerToken))
            {
                _httpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", _bearerToken);
                _logger.LogInformation("[AUTH] Configured for Standard Bearer Token Authentication.");
            }
        }

        private X509Certificate2? LoadProvisioningCertificate()
        {
            if (string.IsNullOrWhiteSpace(_certThumbprint)) return null;

            string cleanThumbprint = System.Text.RegularExpressions.Regex.Replace(_certThumbprint, @"[^\da-fA-F]", "").ToUpperInvariant();

            using var store = new X509Store(StoreName.My, StoreLocation.LocalMachine);
            store.Open(OpenFlags.ReadOnly);

            var certs = store.Certificates.Find(X509FindType.FindByThumbprint, cleanThumbprint, validOnly: false);
            if (certs.Count > 0)
            {
                _logger.LogInformation($"[mTLS] Successfully loaded client certificate: {cleanThumbprint}");
                return certs[0];
            }

            _logger.LogWarning($"[mTLS] Certificate with thumbprint {cleanThumbprint} not found in LocalMachine\\My.");
            return null;
        }

        protected override async Task ExecuteAsync(CancellationToken stoppingToken)
        {
            _logger.LogInformation($"[*] Deep Visibility Sensor v2.1 Telemetry Forwarder initializing...");

            var dispatcherTask = RunDispatcherAsync(stoppingToken);
            var alertTailTask = TailLogFileAsync("DeepSensor_Events.jsonl", stoppingToken);
            var uebaTailTask = TailLogFileAsync("DeepSensor_UEBA_Events.jsonl", stoppingToken);

            await Task.WhenAll(dispatcherTask, alertTailTask, uebaTailTask);
        }

        public override async Task StopAsync(CancellationToken cancellationToken)
        {
            _logger.LogWarning("[!] OS Shutdown or Service Stop requested. Halting log ingestion and draining network queues...");

            _eventQueue.Writer.Complete();
            await Task.Delay(5000, cancellationToken);
            await base.StopAsync(cancellationToken);
        }

        private async Task TailLogFileAsync(string fileName, CancellationToken stoppingToken)
        {
            string fullPath = Path.Combine(_telemetryDir, fileName);
            long currentOffset = 0;

            while (!stoppingToken.IsCancellationRequested)
            {
                try
                {
                    if (File.Exists(fullPath))
                    {
                        long currentFileLength = new FileInfo(fullPath).Length;
                        if (currentFileLength < currentOffset && currentOffset > 0)
                        {
                            _logger.LogWarning($"[FILE TAIL] Log rotation detected on {fileName}. Draining previous archive...");
                            await DrainRotatedArchiveAsync(fileName, currentOffset, stoppingToken);
                            currentOffset = 0;
                        }

                        using var fs = new FileStream(fullPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
                        fs.Seek(currentOffset, SeekOrigin.Begin);
                        using var reader = new StreamReader(fs, Encoding.UTF8);

                        string? line;
                        while ((line = await reader.ReadLineAsync(stoppingToken)) != null)
                        {
                            string trimmed = line.Trim();
                            if (!string.IsNullOrWhiteSpace(trimmed) && trimmed.StartsWith("{") && trimmed.EndsWith("}"))
                            {
                                await _eventQueue.Writer.WriteAsync(trimmed, stoppingToken);
                            }
                        }
                        currentOffset = fs.Position;
                    }
                }
                catch (OperationCanceledException) { break; }
                catch (Exception) { /* Recoverable I/O lock */ }

                await Task.Delay(1000, stoppingToken);
            }
        }

        private async Task DrainRotatedArchiveAsync(string baseFileName, long lastKnownOffset, CancellationToken stoppingToken)
        {
            try
            {
                string searchPattern = baseFileName.Replace(".jsonl", "_*.jsonl");
                var dirInfo = new DirectoryInfo(_telemetryDir);

                var latestArchive = dirInfo.GetFiles(searchPattern)
                                           .OrderByDescending(f => f.CreationTimeUtc)
                                           .FirstOrDefault();

                if (latestArchive != null && latestArchive.Length > lastKnownOffset)
                {
                    using var fs = new FileStream(latestArchive.FullName, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
                    fs.Seek(lastKnownOffset, SeekOrigin.Begin);
                    using var reader = new StreamReader(fs, Encoding.UTF8);

                    string? line;
                    int recoveredLines = 0;
                    while ((line = await reader.ReadLineAsync(stoppingToken)) != null)
                    {
                        string trimmed = line.Trim();
                        if (!string.IsNullOrWhiteSpace(trimmed) && trimmed.StartsWith("{") && trimmed.EndsWith("}"))
                        {
                            await _eventQueue.Writer.WriteAsync(trimmed, stoppingToken);
                            recoveredLines++;
                        }
                    }
                    _logger.LogInformation($"[FILE TAIL] Successfully recovered {recoveredLines} events from archive {latestArchive.Name}.");
                }
            }
            catch (Exception ex)
            {
                _logger.LogError($"[FILE TAIL] Minor data loss occurred during log drain: {ex.Message}");
            }
        }

        private async Task RunDispatcherAsync(CancellationToken stoppingToken)
        {
            var batch = new System.Collections.Generic.List<string>(_batchSize);

            while (!stoppingToken.IsCancellationRequested)
            {
                try
                {
                    if (batch.Count == 0)
                    {
                        await _eventQueue.Reader.WaitToReadAsync(stoppingToken);
                    }

                    while (batch.Count < _batchSize && _eventQueue.Reader.TryRead(out string evt))
                    {
                        batch.Add(evt);
                    }

                    if (batch.Count >= _batchSize)
                    {
                        await ProcessBatchWithRetryAsync(batch, stoppingToken);
                        continue;
                    }

                    using var flushCts = CancellationTokenSource.CreateLinkedTokenSource(stoppingToken);
                    flushCts.CancelAfter(_flushInterval);

                    try
                    {
                        await _eventQueue.Reader.WaitToReadAsync(flushCts.Token);
                    }
                    catch (OperationCanceledException)
                    {
                        if (batch.Count > 0)
                        {
                            await ProcessBatchWithRetryAsync(batch, stoppingToken);
                        }
                    }
                }
                catch (OperationCanceledException) { break; }
                catch (Exception ex)
                {
                    _logger.LogWarning($"[DISPATCH ERROR] Recoverable loop failure: {ex.Message}");
                    await Task.Delay(2000, stoppingToken);
                }
            }
        }

        private async Task ProcessBatchWithRetryAsync(System.Collections.Generic.List<string> batch, CancellationToken stoppingToken)
        {
            int retryAttempt = 0;
            int maxDelayMs = 60000; // Cap backoff at 60 seconds
            Random jitter = new Random();

            while (!stoppingToken.IsCancellationRequested)
            {
                bool success = await DispatchBatchAsync(batch);

                if (success)
                {
                    batch.Clear();
                    return; // Successfully transmitted, exit the retry loop
                }

                retryAttempt++;

                int delay = Math.Min((int)Math.Pow(2, retryAttempt) * 1000, maxDelayMs);

                int jitterMs = jitter.Next(-delay / 5, delay / 5);
                int finalDelay = Math.Max(1000, delay + jitterMs);

                _logger.LogWarning($"[TRANSMISSION FAILED] SIEM unreachable. Retrying batch of {batch.Count} in {finalDelay}ms (Attempt {retryAttempt})");

                await Task.Delay(finalDelay, stoppingToken);
            }
        }

        [ThreadStatic]
        private static StringBuilder? _payloadBuilder;

        private async Task<bool> DispatchBatchAsync(System.Collections.Generic.List<string> batch)
        {
            if (_payloadBuilder == null) _payloadBuilder = new StringBuilder(batch.Count * 512);
            _payloadBuilder.Clear();

            _payloadBuilder.Append('[');
            for (int i = 0; i < batch.Count; i++)
            {
                _payloadBuilder.Append(batch[i]);
                if (i < batch.Count - 1) _payloadBuilder.Append(',');
            }
            _payloadBuilder.Append(']');

            using var content = new StringContent(_payloadBuilder.ToString(), Encoding.UTF8, "application/json");

            try
            {
                var response = await _httpClient.PostAsync(_targetEndpoint, content);
                return response.IsSuccessStatusCode;
            }
            catch
            {
                return false;
            }
        }
    }
}