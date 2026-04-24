using System.Collections.Generic;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using Microsoft.Extensions.Configuration;

namespace CentralConsolidation.Sinks
{
    public class SplunkHecSink : ITelemetrySink
    {
        public string Name => "Splunk";
        private readonly HttpClient _http;
        private readonly string _endpoint;

        public SplunkHecSink(IHttpClientFactory httpFactory, IConfiguration config)
        {
            _http = httpFactory.CreateClient("PooledHttp");
            _endpoint = config["Splunk:Endpoint"];
            _http.DefaultRequestHeaders.Add("Authorization", $"Splunk {config["Splunk:Token"]}");
        }

        public async Task<bool> FlushBatchAsync(List<JsonElement> batch, bool isHotPath)
        {
            var sb = new StringBuilder(batch.Count * 1024);
            foreach (var evt in batch)
            {
                sb.Append("{\"event\":").Append(evt.GetRawText()).Append("}\n");
            }

            using var content = new StringContent(sb.ToString(), Encoding.UTF8, "application/json");
            var response = await _http.PostAsync(_endpoint, content);
            return response.IsSuccessStatusCode;
        }
    }
}