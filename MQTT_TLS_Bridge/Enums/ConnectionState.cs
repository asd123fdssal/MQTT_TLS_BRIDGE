namespace MQTT_TLS_Bridge.Enums
{
    // 연결 상태를 나타내는 열거형(enum)
    public enum ConnectionState
    {
        Disconnected, // 연결 끊김, 0
        Connecting, // 연결 중, 1
        Connected, // 연결됨, 2
        Error, // 오류 발생, 3
    }
}
