using System.Collections.Generic;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using Microsoft.Extensions.Configuration;

namespace CentralConsolidation.Sinks
{
    public class ElasticBulkSink : ITelemetrySink
    {
        public string Name => "Elastic";
        private readonly HttpClient _http;
        private readonly string _endpoint;
        private readonly string _indexInfo;

        public ElasticBulkSink(IHttpClientFactory httpFactory, IConfiguration config)
        {
            _http = httpFactory.CreateClient("PooledHttp");
            _endpoint = config["Elastic:Endpoint"];
            _http.DefaultRequestHeaders.Add("Authorization", $"ApiKey {config["Elastic:ApiKey"]}");
            _indexInfo = $"{{\"index\": {{\"_index\": \"{config["Elastic:Index"]}\"}}}}\n";
        }

        public async Task<bool> FlushBatchAsync(List<JsonElement> batch, bool isHotPath)
        {
            var sb = new StringBuilder(batch.Count * 1024);
            foreach (var evt in batch)
            {
                sb.Append(_indexInfo);
                sb.Append(evt.GetRawText()).Append('\n');
            }

            using var content = new StringContent(sb.ToString(), Encoding.UTF8, "application/x-ndjson");
            var response = await _http.PostAsync(_endpoint, content);
            return response.IsSuccessStatusCode;
        }
    }
}