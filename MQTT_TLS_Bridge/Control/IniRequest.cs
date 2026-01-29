namespace MQTT_TLS_Bridge.Control
{
    // 인스턴스 생성 가능, 상속 불가
    // 이 클래스는 데이터 전달을 위한 DTO(Data Transfer Object) 역할
    public sealed class IniRequest
    {
        // 읽기 전용 멤버 변수
        public string Id { get; }

        public string Command { get; }

        // Key & Value 구조로 된 변수들
        public Dictionary<string, string> Arguments { get; }

        // 생성자
        public IniRequest(string id, string command, Dictionary<string, string> arguments)
        {
            Id = id;
            Command = command;
            Arguments = arguments;
        }
    }
}
