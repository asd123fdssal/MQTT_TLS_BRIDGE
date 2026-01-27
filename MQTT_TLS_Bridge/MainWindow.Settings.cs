using System.Security.Authentication;
using System.Windows;
using System.Windows.Controls;
using Microsoft.Win32;
using MQTT_TLS_Bridge.Publisher;
using MQTT_TLS_Bridge.Settings;
using MQTTnet.Protocol;
using AppClientSettings = MQTT_TLS_Bridge.Settings.ClientSettings;

namespace MQTT_TLS_Bridge
{
    public partial class MainWindow
    {
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
    }
}
