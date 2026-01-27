using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Net;
using System.Security.Authentication;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using MQTT_TLS_Bridge.Control;
using MQTT_TLS_Bridge.Enums;
using MQTT_TLS_Bridge.Publisher;
using MQTTnet.Protocol;

namespace MQTT_TLS_Bridge
{
    public partial class MainWindow
    {
        private async void ServerToggle_Checked(object sender, RoutedEventArgs e)
        {
            try
            {
                var port = ParsePortOrThrow(ServerPortTextBox.Text);
                var bind =
                    ServerAllowRemoteCheckBox.IsChecked == true
                        ? IPAddress.Any
                        : IPAddress.Loopback;

                await StartControlServerAsync(bind, port);

                ServerStatusText.Text = $"{bind}:{port}";
                AppendServerLog($"Control server started on {bind}:{port}");
            }
            catch (Exception ex)
            {
                AppendServerLog($"Control server start failed: {ex.GetType().Name}: {ex.Message}");
                ServerToggle.IsChecked = false;
                ServerStatusText.Text = "Stopped";
            }
        }

        private async void ServerToggle_Unchecked(object sender, RoutedEventArgs e)
        {
            try
            {
                await StopControlServerAsync();
                ServerStatusText.Text = "Stopped";
                AppendServerLog("Control server stopped.");
            }
            catch (Exception ex)
            {
                AppendServerLog($"Control server stop failed: {ex.GetType().Name}: {ex.Message}");
            }
        }

        private async Task StartControlServerAsync(IPAddress bindAddress, int port)
        {
            await _serverLifecycleLock.WaitAsync();
            try
            {
                await StopControlServerAsync_NoLock();

                var server = new IniControlServer(bindAddress, port, HandleControlCommandAsync);

                AttachControlServerEvents(server);

                server.Start(_cts.Token);

                _controlServer = server;
            }
            finally
            {
                _serverLifecycleLock.Release();
            }
        }

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

        private async Task StopControlServerAsync_NoLock()
        {
            var server = _controlServer;
            if (server == null)
                return;

            try
            {
                DetachControlServerEvents(server);
                await server.StopAsync();
            }
            catch (Exception ex)
            {
                AppendClientLog($"Control server stop error: {ex.GetType().Name}: {ex.Message}");
            }
            finally
            {
                _controlServer = null;
            }
        }

        private void AttachControlServerEvents(IniControlServer server)
        {
            _onRawReceived = (remote, raw) => _fileLog.WriteRaw("CTRL", remote, "RX", raw);
            _onRawSent = (remote, raw) => _fileLog.WriteRaw("CTRL", remote, "TX", raw);

            _onCtrlClientConnected = remote =>
                _fileLog.Write(LogServerName, $"CTRL client connected remote={remote}");
            _onCtrlClientDisconnected = remote =>
                _fileLog.Write(LogServerName, $"CTRL client disconnected remote={remote}");

            _onPacketReceived = (remote, id, cmd) =>
                _fileLog.Write(LogServerName, $"CTRL REQ remote={remote} id={id} cmd={cmd}");
            _onPacketSent = (remote, id, ok) =>
                _fileLog.Write(
                    LogServerName,
                    $"CTRL RES remote={remote} id={id} ok={(ok ? "1" : "0")}"
                );

            server.RawReceived += _onRawReceived;
            server.RawSent += _onRawSent;

            server.ClientConnected += _onCtrlClientConnected;
            server.ClientDisconnected += _onCtrlClientDisconnected;

            server.PacketReceived += _onPacketReceived;
            server.PacketSent += _onPacketSent;
        }

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

        private async Task<IniResponse> HandleControlCommandAsync(IniRequest req)
        {
            await _controlLock.WaitAsync();
            try
            {
                await Dispatcher.InvokeAsync(() =>
                {
                    ServerLastCommandText.Text = $"{req.Command} (id={req.Id})";
                });

                AppendServerLog($"REQ id={req.Id} cmd={req.Command}");

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

                AppendServerLog($"RES id={resp.Id} ok={(resp.IsOk ? "1" : "0")}");
                return resp;
            }
            catch (Exception ex)
            {
                AppendServerLog($"ERR id={req.Id} {ex.GetType().Name}: {ex.Message}");
                return IniResponse.Failure(req.Id, ex.GetType().Name, ex.Message);
            }
            finally
            {
                _controlLock.Release();
            }
        }

        private static bool ReadBoolArg(Dictionary<string, string> args, string key, bool fallback)
        {
            if (!args.TryGetValue(key, out var v) || string.IsNullOrWhiteSpace(v))
                return fallback;

            v = v.Trim();
            return v == "1"
                || v.Equals("true", StringComparison.OrdinalIgnoreCase)
                || v.Equals("yes", StringComparison.OrdinalIgnoreCase);
        }

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
        private async Task<IniResponse> CmdBrokerStart(IniRequest req)
        {
            var ui = await UiAsync(() =>
                new
                {
                    PortText = BrokerPortTextBox.Text,
                    PfxPath = (BrokerPfxPathTextBox.Text ?? string.Empty).Trim(),
                    PfxPw = BrokerPfxPasswordBox.Password ?? string.Empty,
                    Tls = ParseSslProtocolsFromUi(BrokerTlsProtocolCombo),
                }
            );

            var port = req.Arguments.TryGetValue("port", out var portText)
                ? ParsePortOrThrow(portText)
                : ParsePortOrThrow(ui.PortText);

            var pfxPath = req.Arguments.TryGetValue("pfx", out var pfx) ? pfx : ui.PfxPath;
            if (string.IsNullOrWhiteSpace(pfxPath))
                return IniResponse.Failure(req.Id, ErrBadRequest, "pfx is empty");

            pfxPath = ResolvePath(pfxPath);

            var password = req.Arguments.TryGetValue("pfxpw", out var pw) ? pw : ui.PfxPw;
            var tls = ReadTlsArg(req.Arguments, "tls", ui.Tls);

            await _brokerService.StartAsync(pfxPath, password, port, tls, _cts.Token);

            return IniResponse.Success(
                req.Id,
                new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
                {
                    ["running"] = "1",
                }
            );
        }

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

        private static int ReadIntArg(Dictionary<string, string> args, string key, int fallback)
        {
            if (!args.TryGetValue(key, out var v) || string.IsNullOrWhiteSpace(v))
                return fallback;

            return int.TryParse(v.Trim(), out var n) ? n : fallback;
        }

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

                ValidationMode = ui.ValidationMode,
                CaCertificatePath = string.IsNullOrWhiteSpace(ui.CaPath)
                    ? null
                    : ResolvePath(ui.CaPath.Trim()),
                PinnedThumbprint = string.IsNullOrWhiteSpace(ui.Thumb) ? null : ui.Thumb.Trim(),
            };
        }

        private async Task<(ConnectionState State, string? Detail)> ConnectAndWaitAsync(
            PublisherConnectionSettings settings,
            int timeoutMs,
            CancellationToken token
        )
        {
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

                await _publisherService.ConnectAsync(settings, token);

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
                _publisherService.ConnectionStateChanged -= Handler;
            }
        }

        private async Task<IniResponse> CmdClientConnect(IniRequest req)
        {
            var timeoutMs = ReadIntArg(req.Arguments, "timeoutMs", 10000);
            if (timeoutMs < 1000)
                timeoutMs = 1000;

            var ui = await CaptureClientDefaultsAsync();
            var settings = BuildClientSettings(req, ui);

            try
            {
                var (state, detail) = await ConnectAndWaitAsync(settings, timeoutMs, _cts.Token);

                if (state == ConnectionState.Connected)
                {
                    return IniResponse.Success(
                        req.Id,
                        new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
                        {
                            ["state"] = "connected",
                        }
                    );
                }

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

        private async Task<IniResponse> CmdClientDisconnect(IniRequest req)
        {
            await _publisherService.DisconnectAsync(_cts.Token);

            return IniResponse.Success(
                req.Id,
                new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
                {
                    ["state"] = "disconnected",
                }
            );
        }

        private async Task<IniResponse> CmdClientPublish(IniRequest req)
        {
            if (
                !req.Arguments.TryGetValue("topic", out var topic)
                || string.IsNullOrWhiteSpace(topic)
            )
                return IniResponse.Failure(req.Id, ErrBadRequest, "topic is missing");

            var qos = ReadQosArg(req.Arguments, "qos", MqttQualityOfServiceLevel.AtMostOnce);
            var retain = ReadBoolArg(req.Arguments, "retain", false);

            string payload = string.Empty;

            if (
                req.Arguments.TryGetValue("payload_b64", out var b64)
                && !string.IsNullOrWhiteSpace(b64)
            )
            {
                var bytes = Convert.FromBase64String(b64);
                payload = Encoding.UTF8.GetString(bytes);
            }
            else if (req.Arguments.TryGetValue("payload", out var plain))
            {
                payload = plain ?? string.Empty;
            }

            await _publisherService.PublishAsync(topic.Trim(), payload, retain, qos, _cts.Token);
            return IniResponse.Success(req.Id);
        }

        private async Task<IniResponse> CmdClientSubscribe(IniRequest req)
        {
            if (
                !req.Arguments.TryGetValue("filter", out var filter)
                || string.IsNullOrWhiteSpace(filter)
            )
                return IniResponse.Failure(req.Id, ErrBadRequest, "filter is missing");

            var qos = ReadQosArg(req.Arguments, "qos", MqttQualityOfServiceLevel.AtMostOnce);

            await _publisherService.SubscribeAsync(filter.Trim(), qos, _cts.Token);
            await UiAsync(() => UpsertSubscription(filter.Trim(), qos));

            return IniResponse.Success(req.Id);
        }

        private async Task<IniResponse> CmdClientUnsubscribe(IniRequest req)
        {
            if (
                !req.Arguments.TryGetValue("filter", out var filter)
                || string.IsNullOrWhiteSpace(filter)
            )
                return IniResponse.Failure(req.Id, ErrBadRequest, "filter is missing");

            await _publisherService.UnsubscribeAsync(filter.Trim(), _cts.Token);
            await UiAsync(() => RemoveSubscription(filter.Trim()));

            return IniResponse.Success(req.Id);
        }
    }
}
