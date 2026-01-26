namespace MQTT_TLS_Bridge.Control
{
    public sealed class IniResponse
    {
        private IniResponse(string id, bool isOk, Dictionary<string, string> values)
        {
            Id = id;
            IsOk = isOk;
            Values = values;
        }

        public string Id { get; }

        public bool IsOk { get; }

        public Dictionary<string, string> Values { get; }

        public static IniResponse Success(string id)
        {
            var values = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
            {
                ["id"] = id,
                ["ok"] = "1",
            };

            return new IniResponse(id, true, values);
        }

        public static IniResponse Success(string id, Dictionary<string, string> values)
        {
            values["id"] = id;
            values["ok"] = "1";

            return new IniResponse(id, true, values);
        }

        public static IniResponse Failure(string id, string err, string msg)
        {
            var values = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
            {
                ["id"] = id,
                ["ok"] = "0",
                ["err"] = err,
                ["msg"] = msg,
            };

            return new IniResponse(id, false, values);
        }
    }
}
