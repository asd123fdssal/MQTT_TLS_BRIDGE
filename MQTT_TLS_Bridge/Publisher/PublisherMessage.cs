namespace MQTT_TLS_Bridge.Publisher
{
    // 해당 클래스는 데이터 전달을 위한 DTO(Data Transfer Object) 역할
    // 상속이 불가능하도록 sealed 키워드 사용
    public sealed class PublisherMessage
    {
        // 아래 3개 항목은 반드시 설정되어야 함
        public required string Topic { get; init; }
        public required string PayloadText { get; init; }
        public required DateTime ReceivedAtUtc { get; init; }
    }
}
