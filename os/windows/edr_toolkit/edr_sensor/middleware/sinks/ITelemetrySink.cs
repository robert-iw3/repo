using System.Collections.Generic;
using System.Text.Json;
using System.Threading.Tasks;

namespace CentralConsolidation.Sinks
{
    public interface ITelemetrySink
    {
        string Name { get; }
        Task<bool> FlushBatchAsync(List<JsonElement> batch, bool isHotPath);
    }
}