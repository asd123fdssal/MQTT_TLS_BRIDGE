using Microsoft.Win32;
using MQTT_TLS_Bridge.Broker;
using MQTT_TLS_Bridge.Enums;
using MQTT_TLS_Bridge.Publisher;
using MQTT_TLS_Bridge.Settings;
using MQTTnet.Protocol;
using System.Collections.Concurrent;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Security.Authentication;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
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
        private readonly ConcurrentDictionary<string, string> _brokerLastByTopic = new(StringComparer.Ordinal);

        private readonly ObservableCollection<string> _clientTopics = [];
        private readonly ConcurrentDictionary<string, string> _clientLastByTopic = new(StringComparer.Ordinal);

        private readonly ObservableCollection<SubscriptionEntry> _subscriptions = [];

        private AppSettings? _lastLoadedSettings;
        private bool _isShuttingDown;

        // Log trimming policy
        private const int MaxLogLines = 200;   // 최대 유지 라인
        private const int TrimLogLines = 200; // 초과 시 한 번에 지울 라인

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
                    ConnectionState.Connected => new SolidColorBrush(Color.FromRgb(0x2E, 0xCC, 0x71)),
                    ConnectionState.Connecting => new SolidColorBrush(Color.FromRgb(0xF1, 0xC4, 0x0F)),
                    ConnectionState.Error => new SolidColorBrush(Color.FromRgb(0xE7, 0x4C, 0x3C)),
                    _ => new SolidColorBrush(Color.FromRgb(0xEC, 0x2B, 0x13))
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

            if (_publisherService != null)
                _publisherService.ConnectionStateChanged -= PublisherService_ConnectionStateChanged;

            _isShuttingDown = true;
            e.Cancel = true;

            _ = ShutdownAsync();
        }

        private async Task ShutdownAsync()
        {
            try
            {
                await _cts.CancelAsync();
                await _publisherService.DisposeAsync();
                await _brokerService.DisposeAsync();
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
                            AppendClientLog($"Application shutdown error: {ex.GetType().Name}: {ex.Message}");
                        }
                    });
                }
                catch (Exception ex)
                {
                    AppendClientLog($"Dispatcher error: {ex.GetType().Name}: {ex.Message}");
                }
            }
        }

        private void ExitButton_Click(object sender, RoutedEventArgs e)
        {
            Close();
        }

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
                // Save 전에 "기존 저장값"을 확보해야 비밀번호가 null로 덮이지 않습니다.
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
                CheckFileExists = true
            };

            if (dlg.ShowDialog(this) == true)
                BrokerPfxPathTextBox.Text = dlg.FileName;
        }

        private void ClientBrowseCaButton_Click(object sender, RoutedEventArgs e)
        {
            var dlg = new OpenFileDialog
            {
                Filter = "Certificate files (*.cer;*.crt;*.pem)|*.cer;*.crt;*.pem|All files (*.*)|*.*",
                CheckFileExists = true
            };

            if (dlg.ShowDialog(this) == true)
                ClientCaCertPathTextBox.Text = dlg.FileName;
        }

        private void ClientTlsValidationModeCombo_SelectionChanged(object sender, SelectionChangedEventArgs e)
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
                    Username = string.IsNullOrWhiteSpace(PublisherUsername.Text) ? null : PublisherUsername.Text.Trim(),
                    Password = PublisherPassword.Password,
                    UseTls = ClientUseTlsToggle.IsChecked == true,
                    AllowUntrustedCertificates = ClientAllowUntrustedToggle.IsChecked == true,
                    SslProtocols = ParseSslProtocolsFromUi(ClientTlsProtocolCombo),
                    ValidationMode = GetSelectedValidationMode(),
                    CaCertificatePath = string.IsNullOrWhiteSpace(ClientCaCertPathTextBox.Text) ? null : ResolvePath(ClientCaCertPathTextBox.Text.Trim()),
                    PinnedThumbprint = string.IsNullOrWhiteSpace(ClientPinnedThumbprintTextBox.Text) ? null : ClientPinnedThumbprintTextBox.Text.Trim()
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

        private void SubscribedTopicListBox_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            if (SubscribedTopicListBox.SelectedItem is not SubscriptionEntry entry)
                return;

            SubTopicFilterTextBox.Text = entry.TopicFilter;
            SubQosCombo.SelectedIndex = entry.Qos switch
            {
                MqttQualityOfServiceLevel.AtLeastOnce => 1,
                MqttQualityOfServiceLevel.ExactlyOnce => 2,
                _ => 0
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

                if (TopicListBox.SelectedItem is string selected && string.Equals(selected, msg.Topic, StringComparison.Ordinal))
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

                if (ClientTopicListBox.SelectedItem is string selected && string.Equals(selected, msg.Topic, StringComparison.Ordinal))
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
                AppendLogLine(BrokerLogTextBox, $"[{DateTime.Now:HH:mm:ss}] {message}\r\n", MaxLogLines, TrimLogLines);
            });
        }

        private void AppendClientLog(string message)
        {
            Dispatcher.Invoke(() =>
            {
                AppendLogLine(ClientLogTextBox, $"[{DateTime.Now:HH:mm:ss}] {message}\r\n", MaxLogLines, TrimLogLines);
            });
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
                Username = string.IsNullOrWhiteSpace(PublisherUsername.Text) ? null : PublisherUsername.Text.Trim(),
                Password = clientPasswordToSave,
                UseTls = ClientUseTlsToggle.IsChecked == true,
                AllowUntrustedCertificates = ClientAllowUntrustedToggle.IsChecked == true,
                SslProtocolsIndex = ClientTlsProtocolCombo.SelectedIndex,
                ValidationModeIndex = ClientTlsValidationModeCombo.SelectedIndex,
                CaCertificatePath = string.IsNullOrWhiteSpace(ClientCaCertPathTextBox.Text) ? null : ClientCaCertPathTextBox.Text.Trim(),
                PinnedThumbprint = string.IsNullOrWhiteSpace(ClientPinnedThumbprintTextBox.Text) ? null : ClientPinnedThumbprintTextBox.Text.Trim(),
                SubTopicFilter = SubTopicFilterTextBox.Text ?? "info/#",
                SubQosIndex = SubQosCombo.SelectedIndex,
                PubTopic = PubTopicTextBox.Text ?? "info/delta/sbms",
                PubPayload = PubPayloadTextBox.Text ?? string.Empty,
                PubQosIndex = PubQosCombo.SelectedIndex,
                PubRetain = PubRetainToggle.IsChecked == true
            };

            var broker = new BrokerSettings
            {
                Port = ParsePortOrThrow(BrokerPortTextBox.Text),
                PfxPath = BrokerPfxPathTextBox.Text?.Trim() ?? "cert\\devcert.pfx",
                PfxPassword = brokerPasswordToSave,
                SslProtocolsIndex = BrokerTlsProtocolCombo.SelectedIndex
            };

            return new AppSettings
            {
                SavePasswords = savePasswords,
                Client = client,
                Broker = broker
            };
        }


        private void ApplySettingsToUi(AppSettings settings)
        {
            SavePasswordsToggle.IsChecked = settings.SavePasswords;

            PublisherHost.Text = settings.Client.Host ?? "127.0.0.1";
            PublisherPort.Text = settings.Client.Port.ToString();
            PublisherClientID.Text = settings.Client.ClientId ?? string.Empty;
            PublisherUsername.Text = settings.Client.Username ?? string.Empty;

            PublisherPassword.Password = settings.SavePasswords ? (settings.Client.Password ?? string.Empty) : string.Empty;

            ClientUseTlsToggle.IsChecked = settings.Client.UseTls;
            ClientAllowUntrustedToggle.IsChecked = settings.Client.AllowUntrustedCertificates;

            ClientTlsProtocolCombo.SelectedIndex = ClampIndex(settings.Client.SslProtocolsIndex, 0, 2);
            ClientTlsValidationModeCombo.SelectedIndex = ClampIndex(settings.Client.ValidationModeIndex, 0, 3);

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
            BrokerPfxPasswordBox.Password = settings.SavePasswords ? (settings.Broker.PfxPassword ?? string.Empty) : string.Empty;
            BrokerTlsProtocolCombo.SelectedIndex = ClampIndex(settings.Broker.SslProtocolsIndex, 0, 2);

            ApplyTlsValidationModeUi();

            // Subscribed list restore (optional)
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
                _ => MqttQualityOfServiceLevel.AtMostOnce
            };
        }

        private static SslProtocols ParseSslProtocolsFromUi(ComboBox combo)
        {
            return combo.SelectedIndex switch
            {
                0 => SslProtocols.Tls13,
                1 => SslProtocols.Tls12,
                2 => SslProtocols.Tls13 | SslProtocols.Tls12,
                _ => SslProtocols.Tls13
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
                _ => TlsValidationMode.Strict
            };
        }

        private static int ClampIndex(int value, int min, int max)
        {
            if (value < min) return min;
            if (value > max) return min;
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

        // 옵션: Subscribed Topics clear
        private void ClearSubscribedTopicsButton_Click(object sender, RoutedEventArgs e)
        {
            _subscriptions.Clear();
            SubscribedTopicListBox.SelectedItem = null;

            AppendClientLog("Subscribed topics cleared.");
        }


    }
}
