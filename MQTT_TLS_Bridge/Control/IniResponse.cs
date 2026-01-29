namespace MQTT_TLS_Bridge.Control
{
    // 인스턴스 생성 가능, 상속 불가
    // 이 클래스는 데이터 전달을 위한 DTO(Data Transfer Object) 역할
    public sealed class IniResponse
    {
        // 읽기 전용 멤버 변수
        public string Id { get; }
        public bool IsOk { get; }

        // Key & Value 구조로 된 응답 값들
        public Dictionary<string, string> Values { get; }

        // 생성자는 private으로 설정하여 외부에서 직접 인스턴스 생성 불가
        private IniResponse(string id, bool isOk, Dictionary<string, string> values)
        {
            Id = id;
            IsOk = isOk;
            Values = values;
        }

        // 성공 응답
        public static IniResponse Success(string id)
        {
            // StringComparer.OrdinalIgnoreCase 의미: 대소문자 구분x ["id" == "ID" == "Id"]
            var values = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
            {
                ["id"] = id,
                ["ok"] = "1",
            };

            return new IniResponse(id, true, values);
        }

        // 성공 응답 + 추가 값
        public static IniResponse Success(string id, Dictionary<string, string> values)
        {
            values["id"] = id;
            values["ok"] = "1";

            return new IniResponse(id, true, values);
        }

        // 실패 응답
        public static IniResponse Failure(string id, string err, string msg)
        {
            // StringComparer.OrdinalIgnoreCase 의미: 대소문자 구분x ["id" == "ID" == "Id"]
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
