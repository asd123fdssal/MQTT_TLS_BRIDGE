using System;
using System.Buffers;
using System.Text;

namespace MQTT_TLS_Bridge.Utils
{
    public static class PayloadUtf8
    {
        public static string Decode(ReadOnlySequence<byte> payload)
        {
            if (payload.IsEmpty)
            {
                return "(empty)";
            }

            if (payload.IsSingleSegment)
            {
                return Encoding.UTF8.GetString(payload.FirstSpan);
            }

            return Encoding.UTF8.GetString(payload.ToArray());
        }

        public static bool TryDecodeBase64(string? base64, out string payloadText)
        {
            // Treat missing/whitespace payloads as invalid so callers can provide a clear error.
            if (string.IsNullOrWhiteSpace(base64))
            {
                payloadText = string.Empty;
                return false;
            }

            try
            {
                var bytes = Convert.FromBase64String(base64);
                payloadText = Encoding.UTF8.GetString(bytes);
                return true;
            }
            catch (FormatException)
            {
                // Invalid Base64 input: return false so callers can respond with a user-facing error.
                payloadText = string.Empty;
                return false;
            }
        }
    }
}
