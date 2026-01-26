namespace MQTT_TLS_Bridge.Control
{
    public sealed class IniRequest
    {
        public string Id { get; }

        public string Command { get; }

        public Dictionary<string, string> Arguments { get; }

        public IniRequest(string id, string command, Dictionary<string, string> arguments)
        {
            Id = id;
            Command = command;
            Arguments = arguments;
        }
    }
}
