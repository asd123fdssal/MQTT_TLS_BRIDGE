using System.Buffers;
using System.Text;

namespace MQTT_TLS_Bridge.Utils
{
    // MQTT 메시지 payload를 사람이 읽는 문자열로 다루기 위한 유틸
    // 인스턴스를 만들지 않고 정적 메서드로만 사용하는 유틸 클래스
    public static class PayloadUtf8
    {
        // ReadOnlySequence<byte> 형태의 payload를 UTF8 문자열로 변환
        public static string Decode(ReadOnlySequence<byte> payload)
        {
            // payload 길이가 0이면 사람이 바로 알 수 있게 (empty)를 반환
            if (payload.IsEmpty)
            {
                return "(empty)";
            }

            // payload가 한 덩어리 메모리로 구성된 경우
            if (payload.IsSingleSegment)
            {
                // UTF8 디코딩해서 추가 복사 없이 문자열을 만듬
                return Encoding.UTF8.GetString(payload.FirstSpan);
            }

            // payload가 여러 세그먼트로 나뉜 경우 먼저 배열로 합친 뒤 UTF8로 디코딩
            return Encoding.UTF8.GetString(payload.ToArray());
        }

        // Base64로 들어온 문자열을 바이트로 풀고 UTF8 문자열로 변환
        public static bool TryDecodeBase64(string? base64, out string payloadText)
        {
            // 입력이 없거나 공백이면 유효하지 않다고 보고 실패 처리
            if (string.IsNullOrWhiteSpace(base64))
            {
                // out 파라미터는 빈 문자열로 초기화
                payloadText = string.Empty;
                return false;
            }

            try
            {
                // Base64 문자열을 바이트 배열로 변환
                var bytes = Convert.FromBase64String(base64);
                // 변환된 바이트를 UTF8 문자열로 만듬
                payloadText = Encoding.UTF8.GetString(bytes);
                // 성공하면 true 반환
                return true;
            }
            catch (FormatException)
            {
                // Base64 입력이 올바르지 않으면 false를 반환해서 호출자가 사용자에게 보여줄 오류를 처리할 수 있게 함
                payloadText = string.Empty;
                return false;
            }
        }
    }
}
