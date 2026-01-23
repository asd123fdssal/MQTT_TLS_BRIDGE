namespace MQTT_TLS_Bridge.Settings
{
    public sealed class AppSettings
    {
        public bool SavePasswords { get; set; }

        public ClientSettings Client { get; set; } = new();

        public BrokerSettings Broker { get; set; } = new();
    }

    public sealed class ClientSettings
    {
        public string Host { get; set; } = "127.0.0.1";
        public int Port { get; set; } = 8883;

        public string? ClientId { get; set; } = "ClientID";
        public string? Username { get; set; }
        public string? Password { get; set; }

        public bool UseTls { get; set; } = true;
        public bool AllowUntrustedCertificates { get; set; }

        public int SslProtocolsIndex { get; set; } = 0;
        public int ValidationModeIndex { get; set; } = 0;

        public string? CaCertificatePath { get; set; }
        public string? PinnedThumbprint { get; set; }

        public string? SubTopicFilter { get; set; } = "info/#";
        public int SubQosIndex { get; set; } = 0;

        public string? PubTopic { get; set; } = "info/delta/sbms";
        public string? PubPayload { get; set; }
        public int PubQosIndex { get; set; } = 0;
        public bool PubRetain { get; set; }
    }

    public sealed class BrokerSettings
    {
        public int Port { get; set; } = 8883;

        public string? PfxPath { get; set; } = "cert\\devcert.pfx";
        public string? PfxPassword { get; set; }

        public int SslProtocolsIndex { get; set; } = 0;
    }
}
