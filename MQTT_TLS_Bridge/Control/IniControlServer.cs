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
        public event Action<string, string, string>? PacketReceived; // remote, id, cmd
        public event Action<string, string, bool>? PacketSent; // remote, id, ok

        public IniControlServer(
            IPAddress bindAddress,
            int port,
            Func<IniRequest, Task<IniResponse>> handler
        )
        {
            _bindAddress = bindAddress;
            _port = port;
            _handler = handler;
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
                    await _internalCts.CancelAsync();
            }
            catch (OperationCanceledException)
            {
                // ignore
            }
            catch
            {
                // ignore
            }

            try
            {
                _listener.Stop();
            }
            catch
            {
                // ignore
            }

            if (_acceptLoopTask != null)
            {
                try
                {
                    await _acceptLoopTask;
                }
                catch (OperationCanceledException)
                { /* ignore */
                }
                catch
                { /* ignore */
                }
            }

            try
            {
                _internalCts?.Dispose();
            }
            catch
            { /* ignore */
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
                    client = await _listener.AcceptTcpClientAsync(token);
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
            var remote = client.Client.RemoteEndPoint?.ToString() ?? "unknown";
            ClientConnected?.Invoke(remote);

            try
            {
                using (client)
                using (var stream = client.GetStream())
                using (
                    var reader = new StreamReader(
                        stream,
                        Encoding.UTF8,
                        false,
                        4096,
                        leaveOpen: true
                    )
                )
                using (
                    var writer = new StreamWriter(
                        stream,
                        new UTF8Encoding(false),
                        4096,
                        leaveOpen: true
                    )
                    {
                        AutoFlush = true,
                    }
                )
                {
                    while (!token.IsCancellationRequested)
                    {
                        var lines = await ReadPacketLinesAsync(reader, token);
                        if (lines == null)
                            return;

                        if (lines.Count == 0)
                            continue;

                        var resp = await ProcessOnePacketAsync(lines, remote);

                        var packetText = IniPacketFormatter.SerializeResponse(resp);
                        await writer.WriteAsync(packetText);

                        PacketSent?.Invoke(remote, resp.Id, resp.IsOk);
                    }
                }
            }
            finally
            {
                ClientDisconnected?.Invoke(remote);
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
                    line = await reader.ReadLineAsync(token);
                }
                catch (OperationCanceledException)
                {
                    return null;
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

            PacketReceived?.Invoke(remote, req.Id, req.Command);

            try
            {
                return await _handler(req);
            }
            catch (Exception ex)
            {
                return IniResponse.Failure(req.Id, ex.GetType().Name, ex.Message);
            }
        }
    }
}
