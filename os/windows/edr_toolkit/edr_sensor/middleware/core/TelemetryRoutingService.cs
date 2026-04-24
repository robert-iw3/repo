using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Configuration;
using System.Text.Json;
using System.Threading.Tasks;
using System.Threading;
using System;
using System.Collections.Generic;
using System.Linq;
using StackExchange.Redis;

public class TelemetryRoutingService : BackgroundService
{
    private readonly IConnectionMultiplexer _redis;
    private readonly IEnumerable<ITelemetrySink> _allSinks;
    private readonly ITelemetrySink[] _hotSinks;
    private readonly ITelemetrySink[] _coldSinks;

    private readonly int _flushBatchSize;
    private readonly string _consumerName;
    private const string StreamName = "telemetry:ingress";
    private const string ConsumerGroup = "telemetry_processors";

    private List<JsonElement> _hotBuffer = new List<JsonElement>();
    private List<JsonElement> _coldBuffer = new List<JsonElement>();

    private const string cNeon = "\x1b[38;2;57;255;20m";
    private const string cOrange = "\x1b[38;2;255;103;0m";
    private const string cReset = "\x1b[0m";

    public TelemetryRoutingService(IConnectionMultiplexer redis, IEnumerable<ITelemetrySink> sinks, IConfiguration config)
    {
        _redis = redis;
        _allSinks = sinks;
        _consumerName = Environment.MachineName + "_" + Guid.NewGuid().ToString("N").Substring(0, 6);

        _flushBatchSize = config.GetValue<int>("Routing:FlushBatchSize", 1000);

        var hotDest = config.GetValue<string>("Routing:HotDestinations", "").Split(',');
        var coldDest = config.GetValue<string>("Routing:ColdDestinations", "").Split(',');

        _hotSinks = _allSinks.Where(s => hotDest.Contains(s.Name, StringComparer.OrdinalIgnoreCase)).ToArray();
        _coldSinks = _allSinks.Where(s => coldDest.Contains(s.Name, StringComparer.OrdinalIgnoreCase)).ToArray();
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        var db = _redis.GetDatabase();
        try { await db.StreamCreateConsumerGroupAsync(StreamName, ConsumerGroup, "0-0", true); } catch { }

        Console.WriteLine($"[*] Worker {_consumerName} initialized. Active Sinks: {_allSinks.Count()}");

        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                var streamEntries = await db.StreamReadGroupAsync(StreamName, ConsumerGroup, _consumerName, ">", count: 100, 2000);

                if (streamEntries.Length == 0)
                {
                    await FlushBuffersAsync(); // Flush if idle
                    continue;
                }

                foreach (var entry in streamEntries)
                {
                    await RouteEventBatchAsync(entry.Values[0].Value, db);
                    await db.StreamAcknowledgeAsync(StreamName, ConsumerGroup, entry.Id);
                }

                if (_hotBuffer.Count >= _flushBatchSize || _coldBuffer.Count >= _flushBatchSize)
                {
                    await FlushBuffersAsync();
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[ROUTING ERROR] {ex.Message}");
                await Task.Delay(2000, stoppingToken);
            }
        }
    }

    private async Task RouteEventBatchAsync(string rawJson, IDatabase db)
    {
        try
        {
            using var doc = JsonDocument.Parse(rawJson);
            if (doc.RootElement.ValueKind != JsonValueKind.Array) return;

            foreach (var evt in doc.RootElement.EnumerateArray())
            {
                string category = evt.TryGetProperty("Category", out var catProp) ? catProp.GetString() ?? "" : "";

                if (category == "TTP_Match" || category == "Sigma_Match" || category == "StaticAlert")
                {
                    string host = evt.GetProperty("ComputerName").GetString();
                    string sigName = evt.GetProperty("SignatureName").GetString();
                    string process = evt.GetProperty("Process").GetString();

                    // Global 60s Redis Deduplication
                    if (await db.StringSetAsync($"dedup:{host}:{sigName}:{process}", "1", TimeSpan.FromSeconds(60), When.NotExists))
                    {
                        Console.WriteLine($"{cOrange}[HOT PATH]{cReset} {host} | {sigName}");
                        _hotBuffer.Add(evt.Clone());
                    }
                }
                else
                {
                    _coldBuffer.Add(evt.Clone());
                }
            }
        }
        catch { /* Drop malformed JSON */ }
    }

    private async Task FlushBuffersAsync()
    {
        var flushTasks = new List<Task>();

        if (_hotBuffer.Count > 0 && _hotSinks.Length > 0)
        {
            var hotPayload = new List<JsonElement>(_hotBuffer);
            _hotBuffer.Clear();
            foreach (var sink in _hotSinks) flushTasks.Add(sink.FlushBatchAsync(hotPayload, true));
        }

        if (_coldBuffer.Count > 0 && _coldSinks.Length > 0)
        {
            var coldPayload = new List<JsonElement>(_coldBuffer);
            _coldBuffer.Clear();
            foreach (var sink in _coldSinks) flushTasks.Add(sink.FlushBatchAsync(coldPayload, false));
        }

        await Task.WhenAll(flushTasks);
    }
}