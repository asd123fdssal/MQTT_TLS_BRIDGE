using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Text;

namespace MQTT_TLS_Bridge.Control
{
    public sealed class IniControlServer
    {
        private const string ErrBadRequest = "BadRequest";

        private readonly IPAddress _bindAddress;
        private readonly int _port;
        private readonly Func<IniRequest, Task<IniResponse>> _handler;

        private TcpListener? _listener;
        private CancellationTokenSource? _internalCts;
        private Task? _acceptLoopTask;

        public event Action<string>? ClientConnected;
        public event Action<string>? ClientDisconnected;

        // remote, id, cmd
        public event Action<string, string, string>? PacketReceived;

        // remote, id, ok
        public event Action<string, string, bool>? PacketSent;

        // remote, raw
        public event Action<string, string>? RawReceived;

        // remote, raw
        public event Action<string, string>? RawSent;

        public IniControlServer(
            IPAddress bindAddress,
            int port,
            Func<IniRequest, Task<IniResponse>> handler
        )
        {
            _bindAddress = bindAddress;
            _port = port;
            _handler = handler ?? throw new ArgumentNullException(nameof(handler));
        }

        public void Start(CancellationToken externalToken)
        {
            if (_listener != null)
                return;

            _internalCts = CancellationTokenSource.CreateLinkedTokenSource(externalToken);

            _listener = new TcpListener(_bindAddress, _port);
            _listener.Start();

            _acceptLoopTask = Task.Run(
                () => AcceptLoopAsync(_internalCts.Token),
                _internalCts.Token
            );
        }

        public async Task StopAsync()
        {
            if (_listener == null)
                return;

            try
            {
                if (_internalCts != null)
                    await _internalCts.CancelAsync().ConfigureAwait(false);
            }
            catch
            {
                // 중지 경로에서의 예외는 종료/정리 흐름을 막지 않음
            }

            try
            {
                _listener.Stop();
            }
            catch
            {
                // 이미 Stop 되었거나 Dispose 상태일 수 있으므로 무시
            }

            if (_acceptLoopTask != null)
            {
                try
                {
                    await _acceptLoopTask.ConfigureAwait(false);
                }
                catch
                {
                    // 종료 중 accept loop 예외는 무시
                }
            }

            try
            {
                _internalCts?.Dispose();
            }
            catch
            {
                // 정리 중 예외 무시
            }

            _internalCts = null;
            _listener = null;
            _acceptLoopTask = null;
        }

        private async Task AcceptLoopAsync(CancellationToken token)
        {
            if (_listener == null)
                return;

            while (!token.IsCancellationRequested)
            {
                TcpClient? client = null;

                try
                {
                    client = await _listener.AcceptTcpClientAsync(token).ConfigureAwait(false);
                }
                catch (OperationCanceledException)
                {
                    client?.Dispose();
                    break;
                }
                catch
                {
                    client?.Dispose();
                    if (token.IsCancellationRequested)
                        break;

                    continue;
                }

                _ = Task.Run(() => HandleClientAsync(client, token), token);
            }
        }

        private async Task HandleClientAsync(TcpClient client, CancellationToken token)
        {
            var remote = SafeRemote(client);
            SafeInvoke(ClientConnected, remote);

            try
            {
                using (client)
                using (var stream = client.GetStream())
                using (
                    var reader = new StreamReader(
                        stream,
                        Encoding.UTF8,
                        detectEncodingFromByteOrderMarks: false,
                        bufferSize: 4096,
                        leaveOpen: true
                    )
                )
                using (
                    var writer = new StreamWriter(
                        stream,
                        new UTF8Encoding(false),
                        bufferSize: 4096,
                        leaveOpen: true
                    )
                    {
                        AutoFlush = true,
                    }
                )
                {
                    while (!token.IsCancellationRequested)
                    {
                        var lines = await ReadPacketLinesAsync(reader, token).ConfigureAwait(false);
                        if (lines == null)
                            return;

                        if (lines.Count == 0)
                            continue;

                        // raw request 기록 (ReadLine이 CRLF를 제거하므로 여기서 복원)
                        RaiseRawReceived(remote, SerializeRawLines(lines));

                        var resp = await ProcessOnePacketAsync(lines, remote).ConfigureAwait(false);

                        var packetText = IniPacketFormatter.SerializeResponse(resp);

                        // raw response 기록 (전송 직전)
                        RaiseRawSent(remote, packetText);

                        await writer.WriteAsync(packetText).ConfigureAwait(false);

                        SafeInvoke(PacketSent, remote, resp.Id, resp.IsOk);
                    }
                }
            }
            finally
            {
                SafeInvoke(ClientDisconnected, remote);
            }
        }

        private static async Task<List<string>?> ReadPacketLinesAsync(
            StreamReader reader,
            CancellationToken token
        )
        {
            var lines = new List<string>();

            while (true)
            {
                string? line;
                try
                {
                    line = await reader.ReadLineAsync(token).ConfigureAwait(false);
                }
                catch
                {
                    return null;
                }

                if (line == null)
                    return null;

                // 빈 줄은 패킷 종료
                if (line.Length == 0)
                    break;

                lines.Add(line);
            }

            return lines;
        }

        private async Task<IniResponse> ProcessOnePacketAsync(List<string> lines, string remote)
        {
            if (!IniPacketFormatter.TryParseRequest(lines, out var req, out var parseError))
                return IniResponse.Failure(Guid.NewGuid().ToString("N"), ErrBadRequest, parseError);

            if (req == null)
                return IniResponse.Failure(
                    Guid.NewGuid().ToString("N"),
                    ErrBadRequest,
                    "request is null."
                );

            SafeInvoke(PacketReceived, remote, req.Id, req.Command);

            try
            {
                return await _handler(req).ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                return IniResponse.Failure(req.Id, ex.GetType().Name, ex.Message);
            }
        }

        private static string SafeRemote(TcpClient client)
        {
            try
            {
                return client.Client.RemoteEndPoint?.ToString() ?? "unknown";
            }
            catch
            {
                return "unknown";
            }
        }

        private void RaiseRawReceived(string remote, string raw)
        {
            var h = RawReceived;
            if (h == null)
                return;

            try
            {
                h(remote, raw);
            }
            catch
            {
                // Raw 로깅은 진단용 보조 기능이므로 실패해도 서버 처리 흐름을 중단하지 않음
            }
        }

        private void RaiseRawSent(string remote, string raw)
        {
            var h = RawSent;
            if (h == null)
                return;

            try
            {
                h(remote, raw);
            }
            catch
            {
                // Raw 로깅은 진단용 보조 기능이므로 실패해도 서버 처리 흐름을 중단하지 않음
            }
        }

        private static string SerializeRawLines(List<string> lines)
        {
            // 요청은 "라인들 + CRLF + CRLF" 형태로 네트워크 패킷을 복원
            // (ReadLine은 CRLF 제거하므로 여기서 재부착)
            var sb = new StringBuilder();

            foreach (var line in lines)
            {
                sb.Append(line ?? string.Empty);
                sb.Append("\r\n");
            }

            sb.Append("\r\n");
            return sb.ToString();
        }

        private static void SafeInvoke(Action<string>? ev, string a1)
        {
            if (ev == null)
                return;

            try
            {
                ev(a1);
            }
            catch
            {
                // 이벤트 핸들러 예외는 외부 소비자 책임이며 서버 루프 안정성을 위해 무시
            }
        }

        private static void SafeInvoke(
            Action<string, string, string>? ev,
            string a1,
            string a2,
            string a3
        )
        {
            if (ev == null)
                return;

            try
            {
                ev(a1, a2, a3);
            }
            catch
            {
                // 이벤트 핸들러 예외는 외부 소비자 책임이며 서버 루프 안정성을 위해 무시
            }
        }

        private static void SafeInvoke(
            Action<string, string, bool>? ev,
            string a1,
            string a2,
            bool a3
        )
        {
            if (ev == null)
                return;

            try
            {
                ev(a1, a2, a3);
            }
            catch
            {
                // 이벤트 핸들러 예외는 외부 소비자 책임이며 서버 루프 안정성을 위해 무시
            }
        }
    }
}
