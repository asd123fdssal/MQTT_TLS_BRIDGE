using System.Security.Authentication;

namespace MQTT_TLS_Bridge.Publisher
{
    public enum TlsValidationMode
    {
        Strict = 0,
        AllowUntrusted = 1,
        CustomCa = 2,
        ThumbprintPinning = 3,
    }

    public sealed class PublisherConnectionSettings
    {
        public required string Host { get; init; }
        public required int Port { get; init; }
        public required string ClientId { get; init; }

        public string? Username { get; init; }
        public string? Password { get; init; }

        public bool UseTls { get; init; } = true;
        public bool AllowUntrustedCertificates { get; init; } = false;

        public SslProtocols SslProtocols { get; init; } = SslProtocols.Tls13;

        public TlsValidationMode ValidationMode { get; init; } = TlsValidationMode.Strict;

        public string? CaCertificatePath { get; init; }

        public string? PinnedThumbprint { get; init; }
    }
}
