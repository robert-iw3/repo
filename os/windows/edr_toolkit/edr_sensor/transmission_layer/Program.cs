using System;
using System.Collections.Generic;
using System.IO;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

namespace DeepSensor.Telemetry
{
    public class Program
    {
        public static void Main(string[] args)
        {
            CreateHostBuilder(args).Build().Run();
        }

        public static IHostBuilder CreateHostBuilder(string[] args) =>
            Host.CreateDefaultBuilder(args)
                .UseWindowsService(options =>
                {
                    options.ServiceName = "DeepSensor_Telemetry";
                })
                .ConfigureAppConfiguration((hostContext, config) =>
                {
                    var iniSettings = ParseIniAotSafe(@"C:\ProgramData\DeepSensor\Config\DeepSensor_Config.ini");
                    config.AddInMemoryCollection(iniSettings!);
                })
                .ConfigureServices((hostContext, services) =>
                {
                    services.AddHostedService<TelemetryForwarder>();
                });

        private static Dictionary<string, string> ParseIniAotSafe(string filePath)
        {
            var result = new Dictionary<string, string>();
            if (!File.Exists(filePath)) return result;

            string currentSection = "";
            foreach (var line in File.ReadAllLines(filePath))
            {
                string trimmed = line.Trim();
                if (string.IsNullOrWhiteSpace(trimmed) || trimmed.StartsWith("#")) continue;

                if (trimmed.StartsWith("[") && trimmed.EndsWith("]"))
                {
                    currentSection = trimmed.Substring(1, trimmed.Length - 2).Trim() + ":";
                    continue;
                }

                int equalsIdx = trimmed.IndexOf('=');
                if (equalsIdx > 0)
                {
                    string key = trimmed.Substring(0, equalsIdx).Trim();
                    string value = trimmed.Substring(equalsIdx + 1).Trim().Trim('"', '\'');
                    result[$"{currentSection}{key}"] = value;
                }
            }
            return result;
        }
    }
}