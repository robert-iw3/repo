using System;
using System.Collections.Generic;
using System.Data;
using System.Data.SqlClient;
using System.Text.Json;
using System.Threading.Tasks;
using Microsoft.Extensions.Configuration;

namespace CentralConsolidation.Sinks
{
    public class SqlBulkSink : ITelemetrySink
    {
        public string Name => "Sql";
        private readonly string _connString;
        private readonly string _hotTable;
        private readonly string _coldTable;

        public SqlBulkSink(IConfiguration config)
        {
            _connString = config["Sql:ConnectionString"];
            _hotTable = config["Sql:HotTable"];
            _coldTable = config["Sql:ColdTable"];
        }

        public async Task<bool> FlushBatchAsync(List<JsonElement> batch, bool isHotPath)
        {
            string targetTable = isHotPath ? _hotTable : _coldTable;

            using var dataTable = new DataTable();
            dataTable.Columns.Add("ComputerName", typeof(string));
            dataTable.Columns.Add("Timestamp", typeof(DateTime));
            dataTable.Columns.Add("Category", typeof(string));
            dataTable.Columns.Add("RawJson", typeof(string));

            foreach (var evt in batch)
            {
                dataTable.Rows.Add(
                    evt.GetProperty("ComputerName").GetString(),
                    evt.GetProperty("Timestamp_UTC").GetDateTime(),
                    evt.GetProperty("Category").GetString(),
                    evt.GetRawText()
                );
            }

            using var connection = new SqlConnection(_connString);
            await connection.OpenAsync();

            using var bulkCopy = new SqlBulkCopy(connection) { DestinationTableName = targetTable };
            await bulkCopy.WriteToServerAsync(dataTable);

            return true;
        }
    }
}