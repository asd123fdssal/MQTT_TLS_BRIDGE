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
    }
}
