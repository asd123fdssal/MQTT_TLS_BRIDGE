namespace MQTT_TLS_Bridge.Settings
{
    // 프로그램이 사용하는 설정 값을 한곳에 모아둔 설정 모델
    // 상속이 불가능하도록 sealed 키워드 사용
    // AppSettings가 최상위 설정이고 그 안에 ClientSettings와 BrokerSettings이 존재

    public sealed class AppSettings
    {
        public bool SavePasswords { get; set; } // 설정 저장 시 비밀번호 저장 여부

        public ClientSettings Client { get; set; } = new(); // 클라이언트 설정

        public BrokerSettings Broker { get; set; } = new(); // 브로커 설정
    }

    // 클라이언트 설정 모델
    public sealed class ClientSettings
    {
        public string Host { get; set; } = "127.0.0.1"; // 브로커 호스트 주소
        public int Port { get; set; } = 8883; // 브로커 포트 번호

        public string? ClientId { get; set; } = "ClientID"; // 클라이언트 ID
        public string? Username { get; set; } // 사용자 이름
        public string? Password { get; set; } // 비밀번호

        public bool UseTls { get; set; } = true; // TLS 사용 여부
        public bool AllowUntrustedCertificates { get; set; } // 신뢰되지 않은 인증서 허용 여부

        public int SslProtocolsIndex { get; set; } = 0; // SSL/TLS 프로토콜 인덱스
        public int ValidationModeIndex { get; set; } = 0; // 인증서 검증 모드 인덱스

        public string? CaCertificatePath { get; set; } // 사용자 지정 CA 인증서 경로
        public string? PinnedThumbprint { get; set; } // 핀닝할 인증서 지문

        public string? SubTopicFilter { get; set; } = "info/#"; // 구독할 토픽 필터
        public int SubQosIndex { get; set; } = 0; // 구독 QoS 인덱스

        public string? PubTopic { get; set; } = "info/delta/sbms"; // 게시할 토픽
        public string? PubPayload { get; set; } // 게시할 페이로드
        public int PubQosIndex { get; set; } = 0; // 게시 QoS 인덱스
        public bool PubRetain { get; set; } // 게시 유지 플래그
    }

    // 브로커 설정 모델
    public sealed class BrokerSettings
    {
        public int Port { get; set; } = 8883; // 브로커 포트 번호

        public string? PfxPath { get; set; } = "cert\\devcert.pfx"; // PFX 인증서 경로
        public string? PfxPassword { get; set; } // PFX 인증서 비밀번호

        public int SslProtocolsIndex { get; set; } = 0; // SSL/TLS 프로토콜 인덱스
    }
}
