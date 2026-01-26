using System.Text;

namespace MQTT_TLS_Bridge.Control
{
    public static class IniPacketFormatter
    {
        public static bool TryParseRequest(
            IReadOnlyList<string> lines,
            out IniRequest? request,
            out string error
        )
        {
            request = null;
            error = string.Empty;

            var dict = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

            foreach (var raw in lines)
            {
                var line = (raw ?? string.Empty).Trim();
                if (line.Length == 0)
                    continue;

                if (line.StartsWith(';') || line.StartsWith('#'))
                    continue;

                var idx = line.IndexOf('=');
                if (idx <= 0)
                    continue;

                var key = line[..idx].Trim();
                var value = line[(idx + 1)..].Trim();

                if (key.Length == 0)
                    continue;

                dict[key] = value;
            }

            if (!dict.TryGetValue("cmd", out var cmd) || string.IsNullOrWhiteSpace(cmd))
            {
                error = "cmd is missing.";
                return false;
            }

            var id =
                dict.TryGetValue("id", out var rawId) && !string.IsNullOrWhiteSpace(rawId)
                    ? rawId.Trim()
                    : Guid.NewGuid().ToString("N");

            dict.Remove("id");
            dict.Remove("cmd");

            request = new IniRequest(id, cmd.Trim(), dict);
            return true;
        }

        public static string SerializeResponse(IniResponse response)
        {
            var sb = new StringBuilder();

            foreach (
                var kv in response.Values.OrderBy(k => k.Key, StringComparer.OrdinalIgnoreCase)
            )
            {
                var key = kv.Key ?? string.Empty;
                var value = SanitizeValue(kv.Value);

                sb.Append(key);
                sb.Append('=');
                sb.Append(value);
                sb.Append("\r\n");
            }

            sb.Append("\r\n");
            return sb.ToString();
        }

        private static string SanitizeValue(string? value)
        {
            return (value ?? string.Empty).Replace("\r", " ").Replace("\n", " ");
        }
    }
}
