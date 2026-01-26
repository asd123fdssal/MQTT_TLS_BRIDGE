using System.Collections.Concurrent;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Diagnostics.CodeAnalysis;
using System.Net;
using System.Security.Authentication;
using System.Text;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using Microsoft.Win32;
using MQTT_TLS_Bridge.Broker;
using MQTT_TLS_Bridge.Control;
using MQTT_TLS_Bridge.Enums;
using MQTT_TLS_Bridge.Logging;
using MQTT_TLS_Bridge.Publisher;
using MQTT_TLS_Bridge.Settings;
using MQTTnet.Protocol;
using Wpf.Ui.Appearance;
using AppClientSettings = MQTT_TLS_Bridge.Settings.ClientSettings;

namespace MQTT_TLS_Bridge
{
    public partial class MainWindow : Window
    {
        private readonly MqttBrokerService _brokerService = new();
        private readonly MqttPublisherService _publisherService = new();
        private readonly CancellationTokenSource _cts = new();

        private readonly ObservableCollection<string> _brokerTopics = [];
        private readonly ConcurrentDictionary<string, string> _brokerLastByTopic = new(
            StringComparer.Ordinal
        );

        private readonly ObservableCollection<string> _clientTopics = [];
        private readonly ConcurrentDictionary<string, string> _clientLastByTopic = new(
            StringComparer.Ordinal
        );

        private readonly ObservableCollection<SubscriptionEntry> _subscriptions = [];

        private Task<T> UiAsync<T>(Func<T> func) => Dispatcher.InvokeAsync(func).Task;

        private Task UiAsync(Action action) => Dispatcher.InvokeAsync(action).Task;

        private IniControlServer? _controlServer;
        private readonly SemaphoreSlim _controlLock = new(1, 1);
        private readonly SemaphoreSlim _serverLifecycleLock = new(1, 1);

        private AppSettings? _lastLoadedSettings;
        private bool _isShuttingDown;

        private const int MaxLogLines = 200;
        private const int TrimLogLines = 100;
        private const int MaxServerLogLines = 300;
        private const int TrimServerLogLines = 150;

        private const string ErrBadRequest = "BadRequest";
        private const string LogServerName = "Server";
        private const int DefaultControlPort = 4811;

        private readonly DailyFileLogger _fileLog = new(
            System.IO.Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "Logs")
        );

        private Action<string, string>? _onRawReceived;
        private Action<string, string>? _onRawSent;

        private Action<string>? _onCtrlClientConnected;
        private Action<string>? _onCtrlClientDisconnected;

        private Action<string, string, string>? _onPacketReceived;
        private Action<string, string, bool>? _onPacketSent;

        public MainWindow()
        {
            InitializeComponent();

            ApplicationThemeManager.Apply(ApplicationTheme.Dark);

            TopicListBox.ItemsSource = _brokerTopics;
            ClientTopicListBox.ItemsSource = _clientTopics;
            SubscribedTopicListBox.ItemsSource = _subscriptions;

            _brokerService.Log += AppendBrokerLog;
            _brokerService.MessageReceived += OnBrokerMessageReceived;

            _publisherService.Log += AppendClientLog;
            _publisherService.MessageReceived += OnClientMessageReceived;

            _publisherService.ConnectionStateChanged += PublisherService_ConnectionStateChanged;
        }

        private void PublisherService_ConnectionStateChanged(ConnectionState state, string? detail)
        {
            Dispatcher.Invoke(() =>
            {
                ConnStatusText.Text = state.ToString();

                ConnLed.Fill = state switch
                {
                    ConnectionState.Connected => new SolidColorBrush(
                        Color.FromRgb(0x2E, 0xCC, 0x71)
                    ),
                    ConnectionState.Connecting => new SolidColorBrush(
                        Color.FromRgb(0xF1, 0xC4, 0x0F)
                    ),
                    ConnectionState.Error => new SolidColorBrush(Color.FromRgb(0xE7, 0x4C, 0x3C)),
                    _ => new SolidColorBrush(Color.FromRgb(0xEC, 0x2B, 0x13)),
                };

                if (state == ConnectionState.Error && !string.IsNullOrWhiteSpace(detail))
                    AppendClientLog($"Client error: {detail}");
            });
        }

        private void Window_Loaded(object sender, RoutedEventArgs e)
        {
            try
            {
                if (ClientTlsValidationModeCombo.SelectedIndex < 0)
                    ClientTlsValidationModeCombo.SelectedIndex = 0;

                ApplyTlsValidationModeUi();

                if (SettingsStore.Exists())
                {
                    _lastLoadedSettings = SettingsStore.Load();
                    ApplySettingsToUi(_lastLoadedSettings);
                    AppendClientLog("Settings loaded.");
                }

                ServerPortTextBox.Text = DefaultControlPort.ToString();

                ServerAllowRemoteCheckBox.IsChecked = false;
                ServerToggle.IsChecked = true;
            }
            catch (Exception ex)
            {
                AppendClientLog($"Load on start failed: {ex.GetType().Name}: {ex.Message}");
            }
        }

        private void Window_Closing(object sender, CancelEventArgs e)
        {
            if (_isShuttingDown)
                return;

            _publisherService.ConnectionStateChanged -= PublisherService_ConnectionStateChanged;

            _isShuttingDown = true;
            e.Cancel = true;

            _ = ShutdownAsync();
        }

        private async Task ShutdownAsync()
        {
            try
            {
                await StopControlServerAsync().ConfigureAwait(false);
                await _cts.CancelAsync().ConfigureAwait(false);

                await _publisherService.DisposeAsync().ConfigureAwait(false);
                await _brokerService.DisposeAsync().ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                AppendClientLog($"Shutdown error: {ex.GetType().Name}: {ex.Message}");
            }
            finally
            {
                try
                {
                    _cts.Dispose();
                }
                catch (Exception ex)
                {
                    AppendClientLog($"CTS dispose error: {ex.GetType().Name}: {ex.Message}");
                }

                try
                {
                    await Dispatcher.InvokeAsync(() =>
                    {
                        try
                        {
                            Application.Current.Shutdown();
                        }
                        catch (Exception ex)
                        {
                            AppendClientLog(
                                $"Application shutdown error: {ex.GetType().Name}: {ex.Message}"
                            );
                        }
                    });
                }
                catch (Exception ex)
                {
                    AppendClientLog($"Dispatcher error: {ex.GetType().Name}: {ex.Message}");
                }

                try
                {
                    await _fileLog.DisposeAsync().ConfigureAwait(false);
                }
                catch (Exception ex)
                {
                    // 종료 단계에서 파일 로그 정리 실패는 복구 불가이며 앱 종료 흐름을 방해하지 않기 위해 무시합니다.
                    AppendClientLog($"FileLog dispose error: {ex.GetType().Name}: {ex.Message}");
                }
            }
        }

        private void ExitButton_Click(object sender, RoutedEventArgs e) => Close();

        private void LoadSettingsButton_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                _lastLoadedSettings = SettingsStore.Load();
                ApplySettingsToUi(_lastLoadedSettings);
                AppendClientLog("Settings loaded.");
            }
            catch (Exception ex)
            {
                AppendClientLog($"Load failed: {ex.GetType().Name}: {ex.Message}");
            }
        }

        private void SaveSettingsButton_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                if (_lastLoadedSettings == null && SettingsStore.Exists())
                    _lastLoadedSettings = SettingsStore.Load();

                var settings = BuildSettingsFromUiPreserveSecrets();
                SettingsStore.Save(settings);

                _lastLoadedSettings = settings;

                AppendClientLog("Settings saved.");
            }
            catch (Exception ex)
            {
                AppendClientLog($"Save failed: {ex.GetType().Name}: {ex.Message}");
            }
        }

        private void BrokerBrowsePfxButton_Click(object sender, RoutedEventArgs e)
        {
            var dlg = new OpenFileDialog
            {
                Filter = "PFX files (*.pfx)|*.pfx|All files (*.*)|*.*",
                CheckFileExists = true,
            };

            if (dlg.ShowDialog(this) == true)
                BrokerPfxPathTextBox.Text = dlg.FileName;
        }

        private void ClientBrowseCaButton_Click(object sender, RoutedEventArgs e)
        {
            var dlg = new OpenFileDialog
            {
                Filter =
                    "Certificate files (*.cer;*.crt;*.pem)|*.cer;*.crt;*.pem|All files (*.*)|*.*",
                CheckFileExists = true,
            };

            if (dlg.ShowDialog(this) == true)
                ClientCaCertPathTextBox.Text = dlg.FileName;
        }

        private void ClientTlsValidationModeCombo_SelectionChanged(
            object sender,
            SelectionChangedEventArgs e
        )
        {
            ApplyTlsValidationModeUi();
        }

        private void ApplyTlsValidationModeUi()
        {
            var mode = GetSelectedValidationMode();

            if (mode == TlsValidationMode.AllowUntrusted)
            {
                ClientAllowUntrustedToggle.IsChecked = true;
                ClientAllowUntrustedToggle.IsEnabled = false;
            }
            else
            {
                ClientAllowUntrustedToggle.IsEnabled = true;
            }

            var isCustomCa = mode == TlsValidationMode.CustomCa;
            var isPinning = mode == TlsValidationMode.ThumbprintPinning;

            if (ClientCaCertPathTextBox != null)
            {
                ClientCaCertPathTextBox.IsEnabled = isCustomCa;
                if (!isCustomCa)
                    ClientCaCertPathTextBox.Text = string.Empty;
            }

            ClientBrowseCaButton?.IsEnabled = isCustomCa;

            if (ClientPinnedThumbprintTextBox != null)
            {
                ClientPinnedThumbprintTextBox.IsEnabled = isPinning;
                if (!isPinning)
                    ClientPinnedThumbprintTextBox.Text = string.Empty;
            }
        }

        private async void BrokerToggle_Checked(object sender, RoutedEventArgs e)
        {
            try
            {
                var port = ParsePortOrThrow(BrokerPortTextBox.Text);

                var pfxPath = (BrokerPfxPathTextBox.Text ?? string.Empty).Trim();
                if (string.IsNullOrWhiteSpace(pfxPath))
                    throw new InvalidOperationException("PFX path is empty.");

                pfxPath = ResolvePath(pfxPath);

                var password = BrokerPfxPasswordBox.Password ?? string.Empty;
                var ssl = ParseSslProtocolsFromUi(BrokerTlsProtocolCombo);

                await _brokerService.StartAsync(pfxPath, password, port, ssl, _cts.Token);
                AppendBrokerLog("Broker started.");
            }
            catch (Exception ex)
            {
                AppendBrokerLog($"Broker start failed: {ex.GetType().Name}: {ex.Message}");
                BrokerToggle.IsChecked = false;
            }
        }

        private async void BrokerToggle_Unchecked(object sender, RoutedEventArgs e)
        {
            try
            {
                await _brokerService.StopAsync(_cts.Token);
                AppendBrokerLog("Broker stopped.");
            }
            catch (Exception ex)
            {
                AppendBrokerLog($"Broker stop failed: {ex.GetType().Name}: {ex.Message}");
            }
        }

        private async void PublisherConnect_Checked(object sender, RoutedEventArgs e)
        {
            try
            {
                var settings = new PublisherConnectionSettings
                {
                    Host = PublisherHost.Text?.Trim() ?? string.Empty,
                    Port = ParsePortOrThrow(PublisherPort.Text),
                    ClientId = BuildClientId(PublisherClientID.Text),
                    Username = string.IsNullOrWhiteSpace(PublisherUsername.Text)
                        ? null
                        : PublisherUsername.Text.Trim(),
                    Password = PublisherPassword.Password,
                    UseTls = ClientUseTlsToggle.IsChecked == true,
                    AllowUntrustedCertificates = ClientAllowUntrustedToggle.IsChecked == true,
                    SslProtocols = ParseSslProtocolsFromUi(ClientTlsProtocolCombo),
                    ValidationMode = GetSelectedValidationMode(),
                    CaCertificatePath = string.IsNullOrWhiteSpace(ClientCaCertPathTextBox.Text)
                        ? null
                        : ResolvePath(ClientCaCertPathTextBox.Text.Trim()),
                    PinnedThumbprint = string.IsNullOrWhiteSpace(ClientPinnedThumbprintTextBox.Text)
                        ? null
                        : ClientPinnedThumbprintTextBox.Text.Trim(),
                };

                await _publisherService.ConnectAsync(settings, _cts.Token);
            }
            catch (Exception ex)
            {
                AppendClientLog($"Client connect failed: {ex.GetType().Name}: {ex.Message}");
                PublisherConnect.IsChecked = false;
            }
        }

        private async void PublisherConnect_Unchecked(object sender, RoutedEventArgs e)
        {
            try
            {
                await _publisherService.DisconnectAsync(_cts.Token);
            }
            catch (Exception ex)
            {
                AppendClientLog($"Client disconnect failed: {ex.GetType().Name}: {ex.Message}");
            }
        }

        private async void SubscribeButton_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                var filter = (SubTopicFilterTextBox.Text ?? string.Empty).Trim();
                if (string.IsNullOrWhiteSpace(filter))
                    throw new InvalidOperationException("Topic filter is empty.");

                var qos = ParseQos(SubQosCombo);

                await _publisherService.SubscribeAsync(filter, qos, _cts.Token);

                UpsertSubscription(filter, qos);
                AppendClientLog($"Subscribed: {filter} (QoS {(int)qos})");
            }
            catch (Exception ex)
            {
                AppendClientLog($"Subscribe failed: {ex.GetType().Name}: {ex.Message}");
            }
        }

        private async void UnsubscribeButton_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                var filter = (SubTopicFilterTextBox.Text ?? string.Empty).Trim();
                if (string.IsNullOrWhiteSpace(filter))
                    throw new InvalidOperationException("Topic filter is empty.");

                await _publisherService.UnsubscribeAsync(filter, _cts.Token);

                RemoveSubscription(filter);
                AppendClientLog($"Unsubscribed: {filter}");
            }
            catch (Exception ex)
            {
                AppendClientLog($"Unsubscribe failed: {ex.GetType().Name}: {ex.Message}");
            }
        }

        private void SubscribedTopicListBox_SelectionChanged(
            object sender,
            SelectionChangedEventArgs e
        )
        {
            if (SubscribedTopicListBox.SelectedItem is not SubscriptionEntry entry)
                return;

            SubTopicFilterTextBox.Text = entry.TopicFilter;
            SubQosCombo.SelectedIndex = entry.Qos switch
            {
                MqttQualityOfServiceLevel.AtLeastOnce => 1,
                MqttQualityOfServiceLevel.ExactlyOnce => 2,
                _ => 0,
            };
        }

        private async void PublishButton_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                var topic = (PubTopicTextBox.Text ?? string.Empty).Trim();
                if (string.IsNullOrWhiteSpace(topic))
                    throw new InvalidOperationException("Topic is empty.");

                var payload = PubPayloadTextBox.Text ?? string.Empty;
                var qos = ParseQos(PubQosCombo);
                var retain = PubRetainToggle.IsChecked == true;

                await _publisherService.PublishAsync(topic, payload, retain, qos, _cts.Token);
            }
            catch (Exception ex)
            {
                AppendClientLog($"Publish failed: {ex.GetType().Name}: {ex.Message}");
            }
        }

        private void ClientTopicListBox_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            var topic = ClientTopicListBox.SelectedItem as string;
            if (string.IsNullOrWhiteSpace(topic))
                return;

            if (_clientLastByTopic.TryGetValue(topic, out var payload))
                ClientLastMessageTextBox.Text = payload;
            else
                ClientLastMessageTextBox.Text = "(no data yet)";
        }

        private void TopicListBox_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            var topic = TopicListBox.SelectedItem as string;
            if (string.IsNullOrWhiteSpace(topic))
                return;

            if (_brokerLastByTopic.TryGetValue(topic, out var payload))
                BrokerDataTextBox.Text = payload;
            else
                BrokerDataTextBox.Text = "(no data yet)";
        }

        private void OnBrokerMessageReceived(BrokerMessage msg)
        {
            _brokerLastByTopic[msg.Topic] = msg.PayloadText;

            Dispatcher.Invoke(() =>
            {
                if (!_brokerTopics.Contains(msg.Topic))
                    _brokerTopics.Add(msg.Topic);

                if (
                    TopicListBox.SelectedItem is string selected
                    && string.Equals(selected, msg.Topic, StringComparison.Ordinal)
                )
                    BrokerDataTextBox.Text = msg.PayloadText;
            });
        }

        private void OnClientMessageReceived(PublisherMessage msg)
        {
            _clientLastByTopic[msg.Topic] = msg.PayloadText;

            Dispatcher.Invoke(() =>
            {
                if (!_clientTopics.Contains(msg.Topic))
                    _clientTopics.Add(msg.Topic);

                if (
                    ClientTopicListBox.SelectedItem is string selected
                    && string.Equals(selected, msg.Topic, StringComparison.Ordinal)
                )
                    ClientLastMessageTextBox.Text = msg.PayloadText;
            });
        }

        private static void AppendLogLine(TextBox textBox, string line, int maxLines, int trimLines)
        {
            textBox.AppendText(line);

            if (textBox.LineCount <= maxLines)
            {
                textBox.ScrollToEnd();
                return;
            }

            if (trimLines < 1)
                trimLines = 1;

            if (trimLines >= textBox.LineCount)
            {
                textBox.Clear();
                return;
            }

            var charIndex = textBox.GetCharacterIndexFromLineIndex(trimLines);
            if (charIndex > 0)
            {
                textBox.Select(0, charIndex);
                textBox.SelectedText = string.Empty;
            }

            textBox.CaretIndex = textBox.Text.Length;
            textBox.ScrollToEnd();
        }

        private void AppendBrokerLog(string message)
        {
            Dispatcher.Invoke(() =>
            {
                AppendLogLine(
                    BrokerLogTextBox,
                    $"[{DateTime.Now:HH:mm:ss}] {message}\r\n",
                    MaxLogLines,
                    TrimLogLines
                );
                _fileLog.Write("BROKER", message);
            });
        }

        private void AppendClientLog(string message)
        {
            Dispatcher.Invoke(() =>
            {
                AppendLogLine(
                    ClientLogTextBox,
                    $"[{DateTime.Now:HH:mm:ss}] {message}\r\n",
                    MaxLogLines,
                    TrimLogLines
                );
                _fileLog.Write("CLIENT", message);
            });
        }

        private void AppendServerLog(string message)
        {
            Dispatcher.Invoke(() =>
            {
                AppendLogLine(
                    ServerLogTextBox,
                    $"[{DateTime.Now:HH:mm:ss}] {message}\r\n",
                    MaxServerLogLines,
                    TrimServerLogLines
                );
                _fileLog.Write(LogServerName, message);
            });
        }

        private void ClearServerLogButton_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                ServerLogTextBox.Clear();
                AppendServerLog("Server log cleared.");
            }
            catch (Exception ex)
            {
                AppendClientLog($"Clear server log failed: {ex.GetType().Name}: {ex.Message}");
            }
        }

        private void ClearClientTopicsButton_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                _clientTopics.Clear();
                _clientLastByTopic.Clear();
                ClientTopicListBox.SelectedItem = null;
                ClientLastMessageTextBox.Text = string.Empty;
                AppendClientLog("Client topic history cleared.");
            }
            catch (Exception ex)
            {
                AppendClientLog($"Clear client topics failed: {ex.GetType().Name}: {ex.Message}");
            }
        }

        private void ClearBrokerTopicsButton_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                _brokerTopics.Clear();
                _brokerLastByTopic.Clear();
                TopicListBox.SelectedItem = null;
                BrokerDataTextBox.Text = string.Empty;
                AppendBrokerLog("Broker topic history cleared.");
            }
            catch (Exception ex)
            {
                AppendBrokerLog($"Clear broker topics failed: {ex.GetType().Name}: {ex.Message}");
            }
        }

        private void ClearSubscribedTopicsButton_Click(object sender, RoutedEventArgs e)
        {
            _subscriptions.Clear();
            SubscribedTopicListBox.SelectedItem = null;
            AppendClientLog("Subscribed topics cleared.");
        }

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

        private AppSettings BuildSettingsFromUiPreserveSecrets()
        {
            var savePasswords = SavePasswordsToggle.IsChecked == true;

            var brokerPasswordTyped = BrokerPfxPasswordBox.Password ?? string.Empty;
            var clientPasswordTyped = PublisherPassword.Password ?? string.Empty;

            string? brokerPasswordToSave = null;
            string? clientPasswordToSave = null;

            if (savePasswords)
            {
                var existingBrokerPwd = _lastLoadedSettings?.Broker?.PfxPassword;
                var existingClientPwd = _lastLoadedSettings?.Client?.Password;

                brokerPasswordToSave = !string.IsNullOrWhiteSpace(brokerPasswordTyped)
                    ? brokerPasswordTyped
                    : existingBrokerPwd;
                clientPasswordToSave = !string.IsNullOrWhiteSpace(clientPasswordTyped)
                    ? clientPasswordTyped
                    : existingClientPwd;

                brokerPasswordToSave ??= string.Empty;
                clientPasswordToSave ??= string.Empty;
            }

            var client = new AppClientSettings
            {
                Host = PublisherHost.Text?.Trim() ?? "127.0.0.1",
                Port = ParsePortOrThrow(PublisherPort.Text),
                ClientId = PublisherClientID.Text?.Trim(),
                Username = string.IsNullOrWhiteSpace(PublisherUsername.Text)
                    ? null
                    : PublisherUsername.Text.Trim(),
                Password = clientPasswordToSave,
                UseTls = ClientUseTlsToggle.IsChecked == true,
                AllowUntrustedCertificates = ClientAllowUntrustedToggle.IsChecked == true,
                SslProtocolsIndex = ClientTlsProtocolCombo.SelectedIndex,
                ValidationModeIndex = ClientTlsValidationModeCombo.SelectedIndex,
                CaCertificatePath = string.IsNullOrWhiteSpace(ClientCaCertPathTextBox.Text)
                    ? null
                    : ClientCaCertPathTextBox.Text.Trim(),
                PinnedThumbprint = string.IsNullOrWhiteSpace(ClientPinnedThumbprintTextBox.Text)
                    ? null
                    : ClientPinnedThumbprintTextBox.Text.Trim(),
                SubTopicFilter = SubTopicFilterTextBox.Text ?? "info/#",
                SubQosIndex = SubQosCombo.SelectedIndex,
                PubTopic = PubTopicTextBox.Text ?? "info/delta/sbms",
                PubPayload = PubPayloadTextBox.Text ?? string.Empty,
                PubQosIndex = PubQosCombo.SelectedIndex,
                PubRetain = PubRetainToggle.IsChecked == true,
            };

            var broker = new BrokerSettings
            {
                Port = ParsePortOrThrow(BrokerPortTextBox.Text),
                PfxPath = BrokerPfxPathTextBox.Text?.Trim() ?? "cert\\devcert.pfx",
                PfxPassword = brokerPasswordToSave,
                SslProtocolsIndex = BrokerTlsProtocolCombo.SelectedIndex,
            };

            return new AppSettings
            {
                SavePasswords = savePasswords,
                Client = client,
                Broker = broker,
            };
        }

        private void ApplySettingsToUi(AppSettings settings)
        {
            SavePasswordsToggle.IsChecked = settings.SavePasswords;

            PublisherHost.Text = settings.Client.Host ?? "127.0.0.1";
            PublisherPort.Text = settings.Client.Port.ToString();
            PublisherClientID.Text = settings.Client.ClientId ?? string.Empty;
            PublisherUsername.Text = settings.Client.Username ?? string.Empty;

            PublisherPassword.Password = settings.SavePasswords
                ? (settings.Client.Password ?? string.Empty)
                : string.Empty;

            ClientUseTlsToggle.IsChecked = settings.Client.UseTls;
            ClientAllowUntrustedToggle.IsChecked = settings.Client.AllowUntrustedCertificates;

            ClientTlsProtocolCombo.SelectedIndex = ClampIndex(
                settings.Client.SslProtocolsIndex,
                0,
                2
            );
            ClientTlsValidationModeCombo.SelectedIndex = ClampIndex(
                settings.Client.ValidationModeIndex,
                0,
                3
            );

            ClientCaCertPathTextBox.Text = settings.Client.CaCertificatePath ?? string.Empty;
            ClientPinnedThumbprintTextBox.Text = settings.Client.PinnedThumbprint ?? string.Empty;

            SubTopicFilterTextBox.Text = settings.Client.SubTopicFilter ?? "info/#";
            SubQosCombo.SelectedIndex = ClampIndex(settings.Client.SubQosIndex, 0, 2);

            PubTopicTextBox.Text = settings.Client.PubTopic ?? "info/delta/sbms";
            PubPayloadTextBox.Text = settings.Client.PubPayload ?? string.Empty;
            PubQosCombo.SelectedIndex = ClampIndex(settings.Client.PubQosIndex, 0, 2);
            PubRetainToggle.IsChecked = settings.Client.PubRetain;

            BrokerPortTextBox.Text = settings.Broker.Port.ToString();
            BrokerPfxPathTextBox.Text = settings.Broker.PfxPath ?? "cert\\devcert.pfx";
            BrokerPfxPasswordBox.Password = settings.SavePasswords
                ? (settings.Broker.PfxPassword ?? string.Empty)
                : string.Empty;
            BrokerTlsProtocolCombo.SelectedIndex = ClampIndex(
                settings.Broker.SslProtocolsIndex,
                0,
                2
            );

            ApplyTlsValidationModeUi();

            _subscriptions.Clear();
        }

        private static int ParsePortOrThrow(string text)
        {
            if (!int.TryParse(text?.Trim(), out var port))
                throw new InvalidOperationException("Port is not a number.");

            if (port < 1 || port > 65535)
                throw new InvalidOperationException("Port is out of range.");

            return port;
        }

        private static string BuildClientId(string? uiValue)
        {
            var cid = uiValue?.Trim();
            if (!string.IsNullOrWhiteSpace(cid))
                return cid;

            return "cli-" + Guid.NewGuid().ToString("N")[..8];
        }

        private static MqttQualityOfServiceLevel ParseQos(ComboBox combo)
        {
            return combo.SelectedIndex switch
            {
                1 => MqttQualityOfServiceLevel.AtLeastOnce,
                2 => MqttQualityOfServiceLevel.ExactlyOnce,
                _ => MqttQualityOfServiceLevel.AtMostOnce,
            };
        }

        private static SslProtocols ParseSslProtocolsFromUi(ComboBox combo)
        {
            return combo.SelectedIndex switch
            {
                0 => SslProtocols.Tls13,
                1 => SslProtocols.Tls12,
                2 => SslProtocols.Tls13 | SslProtocols.Tls12,
                _ => SslProtocols.Tls13,
            };
        }

        private static string ResolvePath(string path)
        {
            if (System.IO.Path.IsPathRooted(path))
                return path;

            return System.IO.Path.Combine(AppDomain.CurrentDomain.BaseDirectory, path);
        }

        private TlsValidationMode GetSelectedValidationMode()
        {
            return ClientTlsValidationModeCombo.SelectedIndex switch
            {
                1 => TlsValidationMode.AllowUntrusted,
                2 => TlsValidationMode.CustomCa,
                3 => TlsValidationMode.ThumbprintPinning,
                _ => TlsValidationMode.Strict,
            };
        }

        private static int ClampIndex(int value, int min, int max)
        {
            if (value < min)
                return min;
            if (value > max)
                return min;
            return value;
        }

        private void UpsertSubscription(string filter, MqttQualityOfServiceLevel qos)
        {
            for (var i = 0; i < _subscriptions.Count; i++)
            {
                if (string.Equals(_subscriptions[i].TopicFilter, filter, StringComparison.Ordinal))
                {
                    _subscriptions[i] = new SubscriptionEntry(filter, qos);
                    return;
                }
            }

            _subscriptions.Add(new SubscriptionEntry(filter, qos));
        }

        private void RemoveSubscription(string filter)
        {
            for (var i = 0; i < _subscriptions.Count; i++)
            {
                if (string.Equals(_subscriptions[i].TopicFilter, filter, StringComparison.Ordinal))
                {
                    _subscriptions.RemoveAt(i);
                    return;
                }
            }
        }

        private sealed record SubscriptionEntry(string TopicFilter, MqttQualityOfServiceLevel Qos)
        {
            public override string ToString() => $"{TopicFilter} (QoS {(int)Qos})";
        }
    }
}
