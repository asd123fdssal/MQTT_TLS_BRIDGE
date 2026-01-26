using System.Globalization;
using System.IO;
using System.Text;

namespace MQTT_TLS_Bridge.Settings
{
    public static class IniProfileStore
    {
        private static readonly string ConfigDir = Path.Combine(
            AppDomain.CurrentDomain.BaseDirectory,
            "Config"
        );
        private static readonly string ProfilesDir = Path.Combine(ConfigDir, "profiles");
        private static readonly string DefaultPath = Path.Combine(ConfigDir, "default.ini");

        private const string SectionMeta = "Meta";
        private const string SectionBroker = "Broker";
        private const string SectionClient = "Client";

        private static readonly Dictionary<string, Action<AppSettings, string>> Appliers =
            BuildAppliers();

        public static List<string> ListProfiles()
        {
            try
            {
                if (!Directory.Exists(ProfilesDir))
                    return [];

                return
                [
                    .. Directory
                        .EnumerateFiles(ProfilesDir, "*.ini", SearchOption.TopDirectoryOnly)
                        .Select(Path.GetFileNameWithoutExtension)
                        .Where(n => !string.IsNullOrWhiteSpace(n))
                        .Select(n => n!)
                        .OrderBy(n => n, StringComparer.OrdinalIgnoreCase),
                ];
            }
            catch
            {
                return [];
            }
        }

        public static AppSettings LoadEffective(string? profileName)
        {
            var settings = new AppSettings();

            ApplyIniFileIfExists(settings, DefaultPath);

            if (!string.IsNullOrWhiteSpace(profileName))
                ApplyIniFileIfExists(settings, GetProfilePath(profileName));

            return settings;
        }

        public static void SaveDefault(AppSettings settings)
        {
            Directory.CreateDirectory(ConfigDir);
            WriteIni(settings, DefaultPath);
        }

        public static void SaveProfile(string profileName, AppSettings settings)
        {
            if (string.IsNullOrWhiteSpace(profileName))
                throw new InvalidOperationException("profile name is empty.");

            Directory.CreateDirectory(ProfilesDir);
            WriteIni(settings, GetProfilePath(profileName));
        }

        public static Dictionary<string, string> Flatten(AppSettings settings)
        {
            var dict = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
            {
                ["savePasswords"] = settings.SavePasswords ? "1" : "0",

                ["client.host"] = settings.Client.Host ?? string.Empty,
                ["client.port"] = settings.Client.Port.ToString(CultureInfo.InvariantCulture),
                ["client.clientId"] = settings.Client.ClientId ?? string.Empty,
                ["client.username"] = settings.Client.Username ?? string.Empty,
                ["client.password"] = settings.Client.Password ?? string.Empty,
                ["client.useTls"] = settings.Client.UseTls ? "1" : "0",
                ["client.allowUntrusted"] = settings.Client.AllowUntrustedCertificates ? "1" : "0",
                ["client.sslProtocolsIndex"] = settings.Client.SslProtocolsIndex.ToString(
                    CultureInfo.InvariantCulture
                ),
                ["client.validationModeIndex"] = settings.Client.ValidationModeIndex.ToString(
                    CultureInfo.InvariantCulture
                ),
                ["client.caCertificatePath"] = settings.Client.CaCertificatePath ?? string.Empty,
                ["client.pinnedThumbprint"] = settings.Client.PinnedThumbprint ?? string.Empty,

                ["client.subTopicFilter"] = settings.Client.SubTopicFilter ?? string.Empty,
                ["client.subQosIndex"] = settings.Client.SubQosIndex.ToString(
                    CultureInfo.InvariantCulture
                ),

                ["client.pubTopic"] = settings.Client.PubTopic ?? string.Empty,
                ["client.pubPayload"] = settings.Client.PubPayload ?? string.Empty,
                ["client.pubQosIndex"] = settings.Client.PubQosIndex.ToString(
                    CultureInfo.InvariantCulture
                ),
                ["client.pubRetain"] = settings.Client.PubRetain ? "1" : "0",

                ["broker.port"] = settings.Broker.Port.ToString(CultureInfo.InvariantCulture),
                ["broker.pfxPath"] = settings.Broker.PfxPath ?? string.Empty,
                ["broker.pfxPassword"] = settings.Broker.PfxPassword ?? string.Empty,
                ["broker.sslProtocolsIndex"] = settings.Broker.SslProtocolsIndex.ToString(
                    CultureInfo.InvariantCulture
                ),
            };

            return dict;
        }

        public static void ApplyPatch(AppSettings target, IReadOnlyDictionary<string, string> patch)
        {
            foreach (var kv in patch)
            {
                var key = (kv.Key ?? string.Empty).Trim();
                if (key.Length == 0)
                    continue;

                var value = (kv.Value ?? string.Empty).Trim();

                var normalizedKey = NormalizeKey(key);

                if (Appliers.TryGetValue(normalizedKey, out var apply))
                    apply(target, value);
            }
        }

        private static void ApplyIniFileIfExists(AppSettings settings, string path)
        {
            if (!File.Exists(path))
                return;

            var patch = ReadIniAsPatch(path);
            ApplyPatch(settings, patch);
        }

        private static string GetProfilePath(string profileName)
        {
            var safe = profileName.Trim();

            foreach (var c in Path.GetInvalidFileNameChars())
                safe = safe.Replace(c, '_');

            return Path.Combine(ProfilesDir, safe + ".ini");
        }

        private static Dictionary<string, string> ReadIniAsPatch(string path)
        {
            var patch = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            var section = string.Empty;

            foreach (var raw in File.ReadAllLines(path, Encoding.UTF8))
            {
                var line = (raw ?? string.Empty).Trim();
                if (line.Length == 0)
                    continue;

                if (line.StartsWith(';') || line.StartsWith('#'))
                    continue;

                if (TryReadSection(line, out var newSection))
                {
                    section = newSection;
                    continue;
                }

                if (!TryReadKeyValue(line, out var key, out var value))
                    continue;

                var dotted = section.Length == 0 ? key : (section + "." + key);
                patch[dotted] = value;
            }

            return patch;
        }

        private static bool TryReadSection(string line, out string section)
        {
            section = string.Empty;

            if (!line.StartsWith('[') || !line.EndsWith(']'))
                return false;

            section = line[1..^1].Trim();
            return true;
        }

        private static bool TryReadKeyValue(string line, out string key, out string value)
        {
            key = string.Empty;
            value = string.Empty;

            var idx = line.IndexOf('=');
            if (idx <= 0)
                return false;

            key = line[..idx].Trim();
            if (key.Length == 0)
                return false;

            value = line[(idx + 1)..].Trim();
            return true;
        }

        private static void WriteIni(AppSettings settings, string path)
        {
            var sb = new StringBuilder();

            sb.AppendLine("[" + SectionMeta + "]");
            sb.AppendLine("savePasswords=" + (settings.SavePasswords ? "1" : "0"));
            sb.AppendLine();

            sb.AppendLine("[" + SectionBroker + "]");
            sb.AppendLine("port=" + settings.Broker.Port.ToString(CultureInfo.InvariantCulture));
            sb.AppendLine("pfxPath=" + (settings.Broker.PfxPath ?? string.Empty));
            sb.AppendLine("pfxPassword=" + (settings.Broker.PfxPassword ?? string.Empty));
            sb.AppendLine(
                "sslProtocolsIndex="
                    + settings.Broker.SslProtocolsIndex.ToString(CultureInfo.InvariantCulture)
            );
            sb.AppendLine();

            sb.AppendLine("[" + SectionClient + "]");
            sb.AppendLine("host=" + (settings.Client.Host ?? string.Empty));
            sb.AppendLine("port=" + settings.Client.Port.ToString(CultureInfo.InvariantCulture));
            sb.AppendLine("clientId=" + (settings.Client.ClientId ?? string.Empty));
            sb.AppendLine("username=" + (settings.Client.Username ?? string.Empty));
            sb.AppendLine("password=" + (settings.Client.Password ?? string.Empty));
            sb.AppendLine("useTls=" + (settings.Client.UseTls ? "1" : "0"));
            sb.AppendLine(
                "allowUntrusted=" + (settings.Client.AllowUntrustedCertificates ? "1" : "0")
            );
            sb.AppendLine(
                "sslProtocolsIndex="
                    + settings.Client.SslProtocolsIndex.ToString(CultureInfo.InvariantCulture)
            );
            sb.AppendLine(
                "validationModeIndex="
                    + settings.Client.ValidationModeIndex.ToString(CultureInfo.InvariantCulture)
            );
            sb.AppendLine(
                "caCertificatePath=" + (settings.Client.CaCertificatePath ?? string.Empty)
            );
            sb.AppendLine("pinnedThumbprint=" + (settings.Client.PinnedThumbprint ?? string.Empty));
            sb.AppendLine("subTopicFilter=" + (settings.Client.SubTopicFilter ?? string.Empty));
            sb.AppendLine(
                "subQosIndex=" + settings.Client.SubQosIndex.ToString(CultureInfo.InvariantCulture)
            );
            sb.AppendLine("pubTopic=" + (settings.Client.PubTopic ?? string.Empty));
            sb.AppendLine("pubPayload=" + (settings.Client.PubPayload ?? string.Empty));
            sb.AppendLine(
                "pubQosIndex=" + settings.Client.PubQosIndex.ToString(CultureInfo.InvariantCulture)
            );
            sb.AppendLine("pubRetain=" + (settings.Client.PubRetain ? "1" : "0"));
            sb.AppendLine();

            File.WriteAllText(path, sb.ToString(), Encoding.UTF8);
        }

        private static Dictionary<string, Action<AppSettings, string>> BuildAppliers()
        {
            var map = new Dictionary<string, Action<AppSettings, string>>(
                StringComparer.OrdinalIgnoreCase
            )
            {
                ["savepasswords"] = (t, v) => t.SavePasswords = ParseBool(v, t.SavePasswords),
            };
            map["meta.savepasswords"] = map["savepasswords"];

            map["broker.port"] = (t, v) =>
            {
                if (TryParseInt(v, out var p))
                    t.Broker.Port = p;
            };

            map["broker.pfxpath"] = (t, v) => t.Broker.PfxPath = v;
            map["broker.pfxpassword"] = (t, v) => t.Broker.PfxPassword = v;

            map["broker.sslprotocolsindex"] = (t, v) =>
            {
                if (TryParseInt(v, out var idx))
                    t.Broker.SslProtocolsIndex = idx;
            };

            map["client.host"] = (t, v) => t.Client.Host = v;

            map["client.port"] = (t, v) =>
            {
                if (TryParseInt(v, out var p))
                    t.Client.Port = p;
            };

            map["client.clientid"] = (t, v) => t.Client.ClientId = v;
            map["client.username"] = (t, v) => t.Client.Username = v;
            map["client.password"] = (t, v) => t.Client.Password = v;

            map["client.usetls"] = (t, v) => t.Client.UseTls = ParseBool(v, t.Client.UseTls);

            map["client.allowuntrusted"] = (t, v) =>
                t.Client.AllowUntrustedCertificates = ParseBool(
                    v,
                    t.Client.AllowUntrustedCertificates
                );
            map["client.allowuntrustedcertificates"] = map["client.allowuntrusted"];

            map["client.sslprotocolsindex"] = (t, v) =>
            {
                if (TryParseInt(v, out var idx))
                    t.Client.SslProtocolsIndex = idx;
            };

            map["client.validationmodeindex"] = (t, v) =>
            {
                if (TryParseInt(v, out var idx))
                    t.Client.ValidationModeIndex = idx;
            };

            map["client.cacertificatepath"] = (t, v) => t.Client.CaCertificatePath = v;
            map["client.capath"] = map["client.cacertificatepath"];

            map["client.pinnedthumbprint"] = (t, v) => t.Client.PinnedThumbprint = v;
            map["client.thumbprint"] = map["client.pinnedthumbprint"];

            map["client.subtopicfilter"] = (t, v) => t.Client.SubTopicFilter = v;

            map["client.subqosindex"] = (t, v) =>
            {
                if (TryParseInt(v, out var idx))
                    t.Client.SubQosIndex = idx;
            };

            map["client.pubtopic"] = (t, v) => t.Client.PubTopic = v;
            map["client.pubpayload"] = (t, v) => t.Client.PubPayload = v;

            map["client.pubqosindex"] = (t, v) =>
            {
                if (TryParseInt(v, out var idx))
                    t.Client.PubQosIndex = idx;
            };

            map["client.pubretain"] = (t, v) =>
                t.Client.PubRetain = ParseBool(v, t.Client.PubRetain);

            return map;
        }

        private static string NormalizeKey(string key)
        {
            var k = (key ?? string.Empty).Trim();

            if (k.Length == 0)
                return string.Empty;

            return k.ToLowerInvariant();
        }

        private static bool ParseBool(string text, bool defaultValue)
        {
            var v = (text ?? string.Empty).Trim().ToLowerInvariant();
            return v switch
            {
                "1" => true,
                "0" => false,
                "true" => true,
                "false" => false,
                "yes" => true,
                "no" => false,
                _ => defaultValue,
            };
        }

        private static bool TryParseInt(string text, out int value)
        {
            return int.TryParse(
                (text ?? string.Empty).Trim(),
                NumberStyles.Integer,
                CultureInfo.InvariantCulture,
                out value
            );
        }
    }
}
