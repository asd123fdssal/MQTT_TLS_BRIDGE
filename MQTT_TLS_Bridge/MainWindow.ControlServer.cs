using System.Diagnostics.CodeAnalysis;
using System.Net;
using System.Security.Authentication;
using System.Windows;
using MQTT_TLS_Bridge.Control;
using MQTT_TLS_Bridge.Enums;
using MQTT_TLS_Bridge.Publisher;
using MQTT_TLS_Bridge.Utils;
using MQTTnet.Protocol;
using static System.Runtime.InteropServices.JavaScript.JSType;

namespace MQTT_TLS_Bridge
{
    // TCP로 INI 패킷을 보내면, 명령을 실행하고 응답을 돌려주는 Control Server
    // MainWindow 클래스의 일부로 정의
    public partial class MainWindow
    {
        // UI 토글을 켰을 때 Control Server를 시작
        private async void ServerToggle_Checked(object sender, RoutedEventArgs e)
        {
            try
            {
                var port = ParsePortOrThrow(ServerPortTextBox.Text); // 서버 포트 텍스트를 숫자로 파싱하고(1~65535) 아니면 예외
                // 외부 접속 허용 체크:
                // true면 IPAddress.Any(0.0.0.0 바인드 → 외부에서도 접속 가능)
                // false면 IPAddress.Loopback(127.0.0.1 → 로컬만
                var bind =
                    ServerAllowRemoteCheckBox.IsChecked == true
                        ? IPAddress.Any
                        : IPAddress.Loopback;

                // 실제 서버 생성/이벤트 연결/Start 수행
                await StartControlServerAsync(bind, port);

                // 성공 시 상태와 로그 출력
                ServerStatusText.Text = $"{bind}:{port}";
                AppendServerLog($"Control server started on {bind}:{port}");
            }
            catch (Exception ex)
            {
                // 실패하면 로그 남기고 토글을 다시 끄고 상태를 Stopped로
                AppendServerLog($"Control server start failed: {ex.GetType().Name}: {ex.Message}");
                ServerToggle.IsChecked = false;
                ServerStatusText.Text = "Stopped";
            }
        }

        // UI 토글을 껐을 때 Control Server를 중지
        private async void ServerToggle_Unchecked(object sender, RoutedEventArgs e)
        {
            try
            {
                // 정상 종료 시 상태/로그 업데이트
                await StopControlServerAsync();
                ServerStatusText.Text = "Stopped";
                AppendServerLog("Control server stopped.");
            }
            catch (Exception ex)
            {
                // 중지 실패해도 앱이 죽지 않게 로그만 남김
                AppendServerLog($"Control server stop failed: {ex.GetType().Name}: {ex.Message}");
            }
        }

        // 서버 시작을 락으로 보호하고, 기존 서버가 있으면 정리한 뒤 새 서버를 생성/시작
        private async Task StartControlServerAsync(IPAddress bindAddress, int port)
        {
            // Start/Stop이 동시에 겹치는 것을 막기 위한 Lifecycle Lock
            await _serverLifecycleLock.WaitAsync();
            try
            {
                // 시작 전에 기존 서버가 있으면 항상 정지/정리
                await StopControlServerAsync_NoLock();

                // Control Server 생성
                // 패킷을 받으면 HandleControlCommandAsync로 요청을 넘김
                var server = new IniControlServer(bindAddress, port, HandleControlCommandAsync);

                // 이벤트 연결
                AttachControlServerEvents(server);
                // 서버 Start
                server.Start(_cts.Token);
                // 현재 서버 인스턴스 보관
                _controlServer = server;
            }
            finally
            {
                // 어떤 경우에도 락 해제
                _serverLifecycleLock.Release();
            }
        }

        // Stop도 Lifecycle Lock 으로 보호해서 안전하게 종료
        private async Task StopControlServerAsync()
        {
            await _serverLifecycleLock.WaitAsync();
            try
            {
                await StopControlServerAsync_NoLock();
            }
            finally
            {
                _serverLifecycleLock.Release();
            }
        }

        // 실제 서버 종료/정리 로직(내부 로직)
        private async Task StopControlServerAsync_NoLock()
        {
            // 서버가 없으면 종료할게 없음
            var server = _controlServer;
            if (server == null)
                return;

            try
            {
                // 이벤트 해제 후 서버 Stop
                DetachControlServerEvents(server);
                await server.StopAsync();
            }
            catch (Exception ex)
            {
                // Stop 중 예외가 나도 controlServer 참조는 정리해서 다음 시작에 문제 없게 함
                AppendClientLog($"Control server stop error: {ex.GetType().Name}: {ex.Message}");
            }
            finally
            {
                _controlServer = null;
            }
        }

        // IniControlServer에서 발생하는 이벤트를 받아 파일 로거에 기록하도록 연결
        private void AttachControlServerEvents(IniControlServer server)
        {
            // RAW 수신/송신 전문을 파일에 기록
            _onRawReceived = (remote, raw) => _fileLog.WriteRaw("CTRL", remote, "RX", raw);
            _onRawSent = (remote, raw) => _fileLog.WriteRaw("CTRL", remote, "TX", raw);

            // 클라이언트 접속/끊김 로그
            _onCtrlClientConnected = remote =>
                _fileLog.Write(LogServerName, $"CTRL client connected remote={remote}");
            _onCtrlClientDisconnected = remote =>
                _fileLog.Write(LogServerName, $"CTRL client disconnected remote={remote}");

            // 파싱된 논리 패킷(REQ/RES) 단위 로그
            _onPacketReceived = (remote, id, cmd) =>
                _fileLog.Write(LogServerName, $"CTRL REQ remote={remote} id={id} cmd={cmd}");
            _onPacketSent = (remote, id, ok) =>
                _fileLog.Write(
                    LogServerName,
                    $"CTRL RES remote={remote} id={id} ok={(ok ? "1" : "0")}"
                );

            // 이벤트 구독 등록
            server.RawReceived += _onRawReceived;
            server.RawSent += _onRawSent;

            server.ClientConnected += _onCtrlClientConnected;
            server.ClientDisconnected += _onCtrlClientDisconnected;

            server.PacketReceived += _onPacketReceived;
            server.PacketSent += _onPacketSent;
        }

        // Attach에서 등록했던 이벤트를 전부 해제하고 핸들러 참조를 null로 만듬
        // 서버 재시작 시 중복 호출 방지, gc가 못 치우는 참조(메모리 누수) 가능성 방지
        private void DetachControlServerEvents(IniControlServer server)
        {
            if (_onRawReceived != null)
                server.RawReceived -= _onRawReceived;
            if (_onRawSent != null)
                server.RawSent -= _onRawSent;

            if (_onCtrlClientConnected != null)
                server.ClientConnected -= _onCtrlClientConnected;
            if (_onCtrlClientDisconnected != null)
                server.ClientDisconnected -= _onCtrlClientDisconnected;

            if (_onPacketReceived != null)
                server.PacketReceived -= _onPacketReceived;
            if (_onPacketSent != null)
                server.PacketSent -= _onPacketSent;

            _onRawReceived = null;
            _onRawSent = null;
            _onCtrlClientConnected = null;
            _onCtrlClientDisconnected = null;
            _onPacketReceived = null;
            _onPacketSent = null;
        }

        // INI 요청을 받아서 cmd별로 동작 수행 후 IniResponse를 생성
        private async Task<IniResponse> HandleControlCommandAsync(IniRequest req)
        {
            // 동시에 여러 명령이 들어오면 상태 꼬임이 생길 수 있어 락
            await _controlLock.WaitAsync();
            try
            {
                // UI는 UI 스레드에서만 수정 가능 → Dispatcher 사용
                await Dispatcher.InvokeAsync(() =>
                {
                    ServerLastCommandText.Text = $"{req.Command} (id={req.Id})";
                });

                AppendServerLog($"REQ id={req.Id} cmd={req.Command}");

                // cmd를 trim + 소문자화 후 switch로 디스패치
                IniResponse resp = req.Command.Trim().ToLowerInvariant() switch
                {
                    "client.connect" => await CmdClientConnect(req),
                    "client.disconnect" => await CmdClientDisconnect(req),
                    "client.publish" => await CmdClientPublish(req),
                    "client.subscribe" => await CmdClientSubscribe(req),
                    "client.unsubscribe" => await CmdClientUnsubscribe(req),
                    "broker.start" => await CmdBrokerStart(req),
                    "broker.stop" => await CmdBrokerStop(req),
                    _ => IniResponse.Failure(
                        req.Id,
                        "UnknownCommand",
                        $"unknown cmd: {req.Command}"
                    ),
                };

                // 처리 결과 로그 남기고 반환
                AppendServerLog($"RES id={resp.Id} ok={(resp.IsOk ? "1" : "0")}");
                return resp;
            }
            catch (Exception ex)
            {
                // 예외가 나도 Failure 응답으로 감싸서 반환
                AppendServerLog($"ERR id={req.Id} {ex.GetType().Name}: {ex.Message}");
                return IniResponse.Failure(req.Id, ex.GetType().Name, ex.Message);
            }
            finally
            {
                // 락은 반드시 Release
                _controlLock.Release();
            }
        }

        // req.Arguments 딕셔너리에서 값을 읽어 형 변환 + 기본값(fallback)을 적용
        private static bool ReadBoolArg(Dictionary<string, string> args, string key, bool fallback)
        {
            if (!args.TryGetValue(key, out var v) || string.IsNullOrWhiteSpace(v))
                return fallback;

            v = v.Trim();
            return v == "1"
                || v.Equals("true", StringComparison.OrdinalIgnoreCase)
                || v.Equals("yes", StringComparison.OrdinalIgnoreCase);
        }

        // req.Arguments 딕셔너리에서 값을 읽어 형 변환 + 기본값(fallback)을 적용
        private static MqttQualityOfServiceLevel ReadQosArg(
            Dictionary<string, string> args,
            string key,
            MqttQualityOfServiceLevel fallback
        )
        {
            if (!args.TryGetValue(key, out var v) || string.IsNullOrWhiteSpace(v))
                return fallback;

            v = v.Trim();
            return v switch
            {
                "2" => MqttQualityOfServiceLevel.ExactlyOnce,
                "1" => MqttQualityOfServiceLevel.AtLeastOnce,
                _ => MqttQualityOfServiceLevel.AtMostOnce,
            };
        }

        // req.Arguments 딕셔너리에서 값을 읽어 형 변환 + 기본값(fallback)을 적용
        private static SslProtocols ReadTlsArg(
            Dictionary<string, string> args,
            string key,
            SslProtocols fallback
        )
        {
            if (!args.TryGetValue(key, out var v) || string.IsNullOrWhiteSpace(v))
                return fallback;

            v = v.Trim();
            return v switch
            {
                "12" => SslProtocols.Tls12,
                "13" => SslProtocols.Tls13,
                "12|13" => SslProtocols.Tls12 | SslProtocols.Tls13,
                "13|12" => SslProtocols.Tls12 | SslProtocols.Tls13,
                _ => fallback,
            };
        }

        [SuppressMessage(
            "Major Code Smell",
            "S4423",
            Justification = "TLS 1.2만 지원하는 기기가 있을 수 있으므로 TLS 1.2를 선택할 수 있도록 유지함."
        )]
        // 브로커 시작 명령을 처리
        private async Task<IniResponse> CmdBrokerStart(IniRequest req)
        {
            // UI에서 기본값을 안전하게 캡처
            var ui = await UiAsync(() =>
                new
                {
                    PortText = BrokerPortTextBox.Text,
                    PfxPath = (BrokerPfxPathTextBox.Text ?? string.Empty).Trim(),
                    PfxPw = BrokerPfxPasswordBox.Password ?? string.Empty,
                    Tls = ParseSslProtocolsFromUi(BrokerTlsProtocolCombo),
                }
            );

            // 요청 파라미터가 있으면 그 값으로, 없으면 UI 값으로
            var port = req.Arguments.TryGetValue("port", out var portText)
                ? ParsePortOrThrow(portText)
                : ParsePortOrThrow(ui.PortText);

            // pfx 경로는 필수, 상대경로면 앱 폴더 기준 절대경로로 바꿈
            var pfxPath = req.Arguments.TryGetValue("pfx", out var pfx) ? pfx : ui.PfxPath;
            if (string.IsNullOrWhiteSpace(pfxPath))
                return IniResponse.Failure(req.Id, ErrBadRequest, "pfx is empty");

            pfxPath = ResolvePath(pfxPath);

            var password = req.Arguments.TryGetValue("pfxpw", out var pw) ? pw : ui.PfxPw;
            var tls = ReadTlsArg(req.Arguments, "tls", ui.Tls);

            // 실제 브로커 시작
            await _brokerService.StartAsync(pfxPath, password, port, tls, _cts.Token);

            // 성공 응답
            return IniResponse.Success(
                req.Id,
                new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
                {
                    ["running"] = "1",
                }
            );
        }

        // 브로커를 중지하고 running=0을 반환
        private async Task<IniResponse> CmdBrokerStop(IniRequest req)
        {
            await _brokerService.StopAsync(_cts.Token);

            return IniResponse.Success(
                req.Id,
                new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
                {
                    ["running"] = "0",
                }
            );
        }

        // UI에 있는 클라이언트 기본값들을 한 덩어리로 묶은 불변 레코드
        private sealed record ClientDefaults(
            string Host,
            string PortText,
            string ClientIdText,
            string UsernameText,
            string Password,
            bool UseTls,
            bool AllowUntrusted,
            SslProtocols Ssl,
            TlsValidationMode ValidationMode,
            string CaPath,
            string Thumb
        );

        // UI에서 host/port/clientId/username/password/tls 설정 등을 읽어서 ClientDefaults를 생성
        private async Task<ClientDefaults> CaptureClientDefaultsAsync()
        {
            return await UiAsync(() =>
                new ClientDefaults(
                    PublisherHost.Text?.Trim() ?? string.Empty,
                    PublisherPort.Text,
                    PublisherClientID.Text,
                    PublisherUsername.Text,
                    PublisherPassword.Password,
                    ClientUseTlsToggle.IsChecked == true,
                    ClientAllowUntrustedToggle.IsChecked == true,
                    ParseSslProtocolsFromUi(ClientTlsProtocolCombo),
                    GetSelectedValidationMode(),
                    ClientCaCertPathTextBox.Text ?? string.Empty,
                    ClientPinnedThumbprintTextBox.Text ?? string.Empty
                )
            );
        }

        // req.Arguments 딕셔너리에서 값을 읽어 형 변환 + 기본값(fallback)을 적용
        private static int ReadIntArg(Dictionary<string, string> args, string key, int fallback)
        {
            if (!args.TryGetValue(key, out var v) || string.IsNullOrWhiteSpace(v))
                return fallback;

            return int.TryParse(v.Trim(), out var n) ? n : fallback;
        }

        // INI 요청의 인자 + UI 기본값을 합쳐 PublisherConnectionSettings를 생성
        private static PublisherConnectionSettings BuildClientSettings(
            IniRequest req,
            ClientDefaults ui
        )
        {
            string? username;

            if (req.Arguments.TryGetValue("username", out var userArg))
                username = string.IsNullOrWhiteSpace(userArg) ? null : userArg.Trim();
            else
                username = string.IsNullOrWhiteSpace(ui.UsernameText)
                    ? null
                    : ui.UsernameText.Trim();

            var host = req.Arguments.TryGetValue("host", out var hostArg) ? hostArg : ui.Host;

            var port = req.Arguments.TryGetValue("port", out var portText)
                ? ParsePortOrThrow(portText)
                : ParsePortOrThrow(ui.PortText);

            var clientId = req.Arguments.TryGetValue("clientId", out var cid)
                ? cid
                : BuildClientId(ui.ClientIdText);

            var password = req.Arguments.TryGetValue("password", out var pass) ? pass : ui.Password;

            return new PublisherConnectionSettings
            {
                Host = host,
                Port = port,
                ClientId = clientId,
                Username = username,
                Password = password,

                UseTls = ReadBoolArg(req.Arguments, "useTls", ui.UseTls),
                AllowUntrustedCertificates = ReadBoolArg(
                    req.Arguments,
                    "allowUntrusted",
                    ui.AllowUntrusted
                ),
                SslProtocols = ReadTlsArg(req.Arguments, "tls", ui.Ssl),

                // ValidationMode는 현재 코드에서 req 인자를 읽지 않고 ui.ValidationMode를 그대로 사용
                ValidationMode = ui.ValidationMode,
                CaCertificatePath = string.IsNullOrWhiteSpace(ui.CaPath)
                    ? null
                    : ResolvePath(ui.CaPath.Trim()), // CA 경로는 UI에서 온 값을 ResolvePath로 절대화
                PinnedThumbprint = string.IsNullOrWhiteSpace(ui.Thumb) ? null : ui.Thumb.Trim(),
            };
        }

        // Connect를 호출한 뒤, _publisherService.ConnectionStateChanged 이벤트를 기다려 연결 상태를 반환
        private async Task<(ConnectionState State, string? Detail)> ConnectAndWaitAsync(
            PublisherConnectionSettings settings,
            int timeoutMs,
            CancellationToken token
        )
        {
            // 이벤트 기반 결과를 await로 기다릴 수 있게 만드는 장치
            var tcs = new TaskCompletionSource<(ConnectionState, string?)>(
                TaskCreationOptions.RunContinuationsAsynchronously
            );

            void Handler(ConnectionState s, string? d)
            {
                if (
                    s == ConnectionState.Connected
                    || s == ConnectionState.Error
                    || s == ConnectionState.Disconnected
                )
                    tcs.TrySetResult((s, d));
            }

            _publisherService.ConnectionStateChanged += Handler;

            try
            {
                using var timeoutCts = new CancellationTokenSource(
                    TimeSpan.FromMilliseconds(timeoutMs)
                );
                using var linked = CancellationTokenSource.CreateLinkedTokenSource(
                    token,
                    timeoutCts.Token
                );

                // 연결을 시작
                await _publisherService.ConnectAsync(settings, token);

                // 이벤트 도착 vs timeout/취소를 경쟁시킴
                var completed = await Task.WhenAny(
                    tcs.Task,
                    Task.Delay(Timeout.InfiniteTimeSpan, linked.Token)
                );
                if (completed != tcs.Task)
                    throw new TimeoutException($"connect timeout ({timeoutMs}ms)");

                return await tcs.Task;
            }
            finally
            {
                // 이벤트 핸들러 해제(중복/누수 방지)
                _publisherService.ConnectionStateChanged -= Handler;
            }
        }

        // INI 명령을 받아 클라이언트를 MQTT 브로커에 연결
        private async Task<IniResponse> CmdClientConnect(IniRequest req)
        {
            // 요청에 timeoutMs가 없으면 기본 10초
            // 너무 작은 값은 최소 1초로 보정
            var timeoutMs = ReadIntArg(req.Arguments, "timeoutMs", 10000);
            if (timeoutMs < 1000)
                timeoutMs = 1000;

            // UI에서 현재 값들을 읽어 기본값으로 삼고 req.Arguments가 있으면 그것으로 덮어씀
            var ui = await CaptureClientDefaultsAsync();
            var settings = BuildClientSettings(req, ui);

            try
            {
                // 내부적으로 ConnectAsync 호출 후 ConnectionStateChanged 이벤트가
                // Connected / Error / Disconnected 중 하나가 될 때까지 기다림
                var (state, detail) = await ConnectAndWaitAsync(settings, timeoutMs, _cts.Token);

                if (state == ConnectionState.Connected)
                {
                    // 성공 응답
                    return IniResponse.Success(
                        req.Id,
                        new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
                        {
                            ["state"] = "connected",
                        }
                    );
                }

                // 실패 응답
                var msg = string.IsNullOrWhiteSpace(detail) ? state.ToString() : detail!;
                return IniResponse.Failure(req.Id, "ConnectFailed", msg);
            }
            catch (TimeoutException ex)
            {
                return IniResponse.Failure(req.Id, "Timeout", ex.Message);
            }
            catch (Exception ex)
            {
                return IniResponse.Failure(req.Id, ex.GetType().Name, ex.Message);
            }
        }

        // INI 명령(client.disconnect)을 받아 현재 MQTT 연결을 끊음
        private async Task<IniResponse> CmdClientDisconnect(IniRequest req)
        {
            // 연결 끊기 호출
            await _publisherService.DisconnectAsync(_cts.Token);

            // 성공 응답
            return IniResponse.Success(
                req.Id,
                new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
                {
                    ["state"] = "disconnected",
                }
            );
        }

        // INI 명령을 받아 topic으로 payload를 publish
        private async Task<IniResponse> CmdClientPublish(IniRequest req)
        {
            // topic 필수 체크
            if (
                !req.Arguments.TryGetValue("topic", out var topic)
                || string.IsNullOrWhiteSpace(topic)
            )
                return IniResponse.Failure(req.Id, ErrBadRequest, "topic is missing");

            // QoS / retain 읽기
            var qos = ReadQosArg(req.Arguments, "qos", MqttQualityOfServiceLevel.AtMostOnce);
            var retain = ReadBoolArg(req.Arguments, "retain", false);

            // payload 결정(우선순위: payload_b64 → payload → empty)
            string payload = string.Empty;

            if (
                req.Arguments.TryGetValue("payload_b64", out var b64)
                && !string.IsNullOrWhiteSpace(b64)
            )
            {
                if (!PayloadUtf8.TryDecodeBase64(b64, out payload))
                    return IniResponse.Failure(req.Id, ErrBadRequest, "payload_b64 is invalid");
            }
            else if (req.Arguments.TryGetValue("payload", out var plain))
            {
                payload = plain ?? string.Empty;
            }

            // publish 실행
            await _publisherService.PublishAsync(topic.Trim(), payload, retain, qos, _cts.Token);
            return IniResponse.Success(req.Id);
        }

        // INI 명령(client.subscribe)을 받아 topic filter로 subscribe
        private async Task<IniResponse> CmdClientSubscribe(IniRequest req)
        {
            // filter 필수 체크
            if (
                !req.Arguments.TryGetValue("filter", out var filter)
                || string.IsNullOrWhiteSpace(filter)
            )
                return IniResponse.Failure(req.Id, ErrBadRequest, "filter is missing");

            // QoS 읽기
            var qos = ReadQosArg(req.Arguments, "qos", MqttQualityOfServiceLevel.AtMostOnce);

            // subscribe 실행
            await _publisherService.SubscribeAsync(filter.Trim(), qos, _cts.Token);
            // UI 구독 목록 반영
            await UiAsync(() => UpsertSubscription(filter.Trim(), qos));

            //성공 응답
            return IniResponse.Success(req.Id);
        }

        //INI 명령(client.unsubscribe)을 받아 topic filter 구독을 해제
        private async Task<IniResponse> CmdClientUnsubscribe(IniRequest req)
        {
            // filter 필수 체크
            if (
                !req.Arguments.TryGetValue("filter", out var filter)
                || string.IsNullOrWhiteSpace(filter)
            )
                return IniResponse.Failure(req.Id, ErrBadRequest, "filter is missing");

            // unsubscribe 실행
            await _publisherService.UnsubscribeAsync(filter.Trim(), _cts.Token);
            // UI 구독 목록에서 제거
            await UiAsync(() => RemoveSubscription(filter.Trim()));

            // 성공 응답
            return IniResponse.Success(req.Id);
        }
    }
}
