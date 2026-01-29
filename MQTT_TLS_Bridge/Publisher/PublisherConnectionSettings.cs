using System.Security.Authentication;

namespace MQTT_TLS_Bridge.Publisher
{
    public enum TlsValidationMode
    {
        Strict = 0, // 기본 검증을 엄격하게 함. 일반적으로 신뢰할 수 있는 CA 체인 + 만료/호스트명 등이 정상이어야 통과
        AllowUntrusted = 1, // 신뢰되지 않은 인증서(자체서명 등)도 허용
        CustomCa = 2, // OS 기본 신뢰 저장소 대신 지정한 CA 인증서 파일을 신뢰 기준으로 사용
        ThumbprintPinning = 3, // CA 체인 대신 특정 인증서 지문(thumbprint)이 맞는지만 확인
    }

    // Publihser의 연결 설정을 나타내는 클래스
    // 인스턴스 생성은 가능하나, 상속은 불가함
    public sealed class PublisherConnectionSettings
    {
        // 아래 3 항목은 반드시 설정되어야 함
        public required string Host { get; init; }
        public required int Port { get; init; }
        public required string ClientId { get; init; }

        // 아래 2 항목은 nullable
        public string? Username { get; init; }
        public string? Password { get; init; }

        // 보안 관련 설정
        public bool UseTls { get; init; } = true;
        public bool AllowUntrustedCertificates { get; init; } = false;

        public SslProtocols SslProtocols { get; init; } = SslProtocols.Tls13;

        public TlsValidationMode ValidationMode { get; init; } = TlsValidationMode.Strict;

        public string? CaCertificatePath { get; init; }

        public string? PinnedThumbprint { get; init; }
    }
}
