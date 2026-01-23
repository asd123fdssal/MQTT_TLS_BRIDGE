namespace MQTT_TLS_Bridge.Publisher
{
    public sealed class PublisherMessage
    {
        public required string Topic { get; init; }
        public required string PayloadText { get; init; }
        public required DateTime ReceivedAtUtc { get; init; }
    }
}
