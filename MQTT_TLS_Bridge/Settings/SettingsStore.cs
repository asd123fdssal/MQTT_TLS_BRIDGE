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
                // Store settings under the app base directory to avoid user profile ambiguity.
                var dir = Path.Combine(AppContext.BaseDirectory, ConfigFolderName);
                return Path.Combine(dir, FileName);
            }
        }

        public static bool Exists() => File.Exists(SettingsPath);

        private static readonly JsonSerializerOptions JsonIndentedOptions = new()
        {
            WriteIndented = true,
        };

        public static void Save(AppSettings settings)
        {
            var dir = Path.GetDirectoryName(SettingsPath)!;
            Directory.CreateDirectory(dir);

            // Persist with indentation to keep settings readable for manual inspection.
            var json = JsonSerializer.Serialize(settings, JsonIndentedOptions);

            File.WriteAllText(SettingsPath, json);
        }

        public static AppSettings Load()
        {
            var path = SettingsPath;
            if (!File.Exists(path))
                throw new FileNotFoundException("Settings file not found.", path);

            var json = File.ReadAllText(path);

            var settings =
                JsonSerializer.Deserialize<AppSettings>(json)
                ?? throw new InvalidOperationException("Settings file is invalid.");
            settings.Client ??= new ClientSettings();
            settings.Broker ??= new BrokerSettings();

            if (!settings.SavePasswords)
            {
                // Drop sensitive secrets when the user opted out of saving passwords.
                settings.Client.Password = null;
                settings.Broker.PfxPassword = null;
            }

            return settings;
        }
    }
}
