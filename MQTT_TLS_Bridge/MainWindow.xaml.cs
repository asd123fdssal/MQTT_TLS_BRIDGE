using System.Collections.Concurrent;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Diagnostics;
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
using Wpf.Ui.Tray.Controls;
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

        private bool _exitRequested;

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

        private async void Window_Loaded(object sender, RoutedEventArgs e)
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
                AppTrayIcon.Register();
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

            if (!_exitRequested)
            {
                e.Cancel = true;
                Hide();
                return;
            }

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
                try
                {
                    await Dispatcher.InvokeAsync(() =>
                    {
                        try
                        {
                            AppTrayIcon.Unregister();
                            AppTrayIcon.Dispose();
                        }
                        catch
                        {
                            // 트레이 해제
                        }
                    });
                }
                catch
                {
                    // 트레이 해제
                }
            }
        }

        private void ExitButton_Click(object sender, RoutedEventArgs e) => Close();

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

        private void AppTrayIcon_LeftDoubleClick(NotifyIcon sender, RoutedEventArgs e)
        {
            RestoreFromTray();
        }

        private void TrayOpen_Click(object sender, RoutedEventArgs e)
        {
            RestoreFromTray();
        }

        private void TrayExit_Click(object sender, RoutedEventArgs e)
        {
            _exitRequested = true;
            Close();
        }

        private void RestoreFromTray()
        {
            Show();
            WindowState = WindowState.Normal;
            Activate();
            Topmost = true;
            Topmost = false;
            Focus();
        }
    }
}
