using System.IO;
using System.Text.Json;

namespace MQTT_TLS_Bridge.Settings
{
    public static class SettingsStore
    {
        private const string ConfigFolderName = "Config";
        private const string FileName = "settings.json";

        public static string SettingsPath
        {
            get
            {
                var dir = Path.Combine(AppContext.BaseDirectory, ConfigFolderName);
                return Path.Combine(dir, FileName);
            }
        }

        public static bool Exists() => File.Exists(SettingsPath);

        public static void Save(AppSettings settings)
        {
            var dir = Path.GetDirectoryName(SettingsPath)!;
            Directory.CreateDirectory(dir);

            var json = JsonSerializer.Serialize(settings, new JsonSerializerOptions
            {
                WriteIndented = true
            });

            File.WriteAllText(SettingsPath, json);
        }

        public static AppSettings Load()
        {
            var path = SettingsPath;
            if (!File.Exists(path))
                throw new FileNotFoundException("Settings file not found.", path);

            var json = File.ReadAllText(path);

            var settings = JsonSerializer.Deserialize<AppSettings>(json);
            if (settings == null)
                throw new InvalidOperationException("Settings file is invalid.");

            settings.Client ??= new ClientSettings();
            settings.Broker ??= new BrokerSettings();

            if (!settings.SavePasswords)
            {
                settings.Client.Password = null;
                settings.Broker.PfxPassword = null;
            }

            return settings;
        }
    }
}
