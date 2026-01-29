using System.Text;

namespace MQTT_TLS_Bridge.Control
{
    // INI 형태의 제어 패킷을 처리하는 유틸
    // 인스턴스를 만들지 않고 정적 메서드로만 사용하는 유틸 클래스
    public static class IniPacketFormatter
    {
        // INI 형식의 요청 라인들을 읽어서 요청 객체로 변환
        public static bool TryParseRequest(
            IReadOnlyList<string> lines, // INI 파일의 각 라인
            out IniRequest? request, // 파싱된 요청 객체
            out string error // 오류 메시지
        )
        {
            // 실패 케이스에서도 호출자가 안전하게 값을 사용할 수 있도록 기본값을 세팅
            request = null;
            error = string.Empty;

            // 키를 대소문자 구분 없이 처리
            var dict = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

            foreach (var raw in lines)
            {
                // 공백만 있는 라인은 무시
                var line = (raw ?? string.Empty).Trim();
                if (line.Length == 0)
                    continue;

                // ; 또는 # 로 시작하는 라인은 주석으로 보고 무시
                if (line.StartsWith(';') || line.StartsWith('#'))
                    continue;

                // = 기준으로 key와 value를 나눔
                // = 가 없거나 맨 앞에 있으면 유효하지 않으므로 무시
                var idx = line.IndexOf('=');
                if (idx <= 0)
                    continue;

                var key = line[..idx].Trim();
                var value = line[(idx + 1)..].Trim();

                // key가 비어 있으면 무시
                if (key.Length == 0)
                    continue;

                dict[key] = value;
            }

            // cmd가 없거나 비어 있으면 실패로 처리하고 error
            if (!dict.TryGetValue("cmd", out var cmd) || string.IsNullOrWhiteSpace(cmd))
            {
                error = "cmd is missing.";
                return false;
            }

            var id =
                dict.TryGetValue("id", out var rawId) && !string.IsNullOrWhiteSpace(rawId)
                    ? rawId.Trim() // id가 있으면 trim해서 사용
                    : Guid.NewGuid().ToString("N"); // id가 없으면 새로운 GUID를 생성

            // id와 cmd는 IniRequest의 전용 필드로 옮기고 딕셔너리에서는 제거
            dict.Remove("id");
            dict.Remove("cmd");

            // 남은 dict는 추가 파라미터로 IniRequest에 전달
            request = new IniRequest(id, cmd.Trim(), dict);
            return true;
        }

        // IniResponse.Values 딕셔너리를 INI 텍스트로 변환
        public static string SerializeResponse(IniResponse response)
        {
            // 문자열을 여러 번 붙일 때 성능을 위해 사용
            var sb = new StringBuilder();

            foreach (
                // 키를 대소문자 무시 기준으로 정렬
                var kv in response.Values.OrderBy(k => k.Key, StringComparer.OrdinalIgnoreCase)
            )
            {
                // 키가 null이면 빈 문자열로 처리
                var key = kv.Key ?? string.Empty;
                // 값은 SanitizeValue로 줄바꿈 제거 처리 후 사용
                var value = SanitizeValue(kv.Value);

                // CRLF를 사용해 줄 단위로 구분
                sb.Append(key);
                sb.Append('=');
                sb.Append(value);
                sb.Append("\r\n");
            }

            sb.Append("\r\n");
            return sb.ToString();
        }

        // 응답 값에 줄바꿈이 포함되면 INI 라인 구조가 깨지므로 줄바꿈 문자를 공백
        private static string SanitizeValue(string? value)
        {
            // null이면 빈 문자열, CR과 LF를 공백으로 바꿔 한 줄로 변경
            return (value ?? string.Empty).Replace("\r", " ").Replace("\n", " ");
        }
    }
}
