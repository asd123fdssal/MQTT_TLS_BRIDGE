using System.Security.AccessControl;
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
    // 설정 저장/로드 및 관련 UI 이벤트 처리
    // MainWindow 클래스의 일부로 정의
    public partial class MainWindow
    {
        // settings.json을 로드해서 UI에 반영하고 로그를 남김
        private void LoadSettingsButton_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                // 파일에서 AppSettings를 읽고(_lastLoadedSettings에 보관)
                _lastLoadedSettings = SettingsStore.Load();
                // UI 컨트롤들에 값을 채움
                ApplySettingsToUi(_lastLoadedSettings);
                // 클라이언트 로그에 성공 메시지
                AppendClientLog("Settings loaded.");
            }
            catch (Exception ex)
            {
                // 실패하면 예외 타입/메시지를 로그로 남김
                AppendClientLog($"Load failed: {ex.GetType().Name}: {ex.Message}");
            }
        }

        // 현재 UI 값을 설정 객체로 만들고 settings.json에 저장
        private void SaveSettingsButton_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                // 마지막 로드한 설정이 없더라도, 파일이 이미 존재하면 로드해서 기존 비밀번호 유지에 쓸 기반을 만듬
                if (_lastLoadedSettings == null && SettingsStore.Exists())
                    _lastLoadedSettings = SettingsStore.Load();

                // UI → AppSettings로 변환
                var settings = BuildSettingsFromUiPreserveSecrets();
                // 파일 저장
                SettingsStore.Save(settings);

                // 마지막 설정 업데이트
                _lastLoadedSettings = settings;

                // 성공 로그
                AppendClientLog("Settings saved.");
            }
            catch (Exception ex)
            {
                // 실패 로그
                AppendClientLog($"Save failed: {ex.GetType().Name}: {ex.Message}");
            }
        }

        // PFX 파일 선택 다이얼로그를 띄워서 선택된 경로를 TextBox에 입력
        private void BrokerBrowsePfxButton_Click(object sender, RoutedEventArgs e)
        {
            // pfx만 우선 보이게 필터 설정
            var dlg = new OpenFileDialog
            {
                Filter = "PFX files (*.pfx)|*.pfx|All files (*.*)|*.*",
                CheckFileExists = true,
            };

            // 사용자가 확인을 누르면 파일 경로를 UI
            if (dlg.ShowDialog(this) == true)
                BrokerPfxPathTextBox.Text = dlg.FileName;
        }

        // CA 인증서 파일(cer/crt/pem) 선택 다이얼로그를 띄워 경로를 TextBox에 입력
        private void ClientBrowseCaButton_Click(object sender, RoutedEventArgs e)
        {
            // cer/crt/pem 파일만 보이게 필터 설정
            var dlg = new OpenFileDialog
            {
                Filter =
                    "Certificate files (*.cer;*.crt;*.pem)|*.cer;*.crt;*.pem|All files (*.*)|*.*",
                CheckFileExists = true,
            };

            // 사용자가 확인을 누르면 파일 경로를 UI
            if (dlg.ShowDialog(this) == true)
                ClientCaCertPathTextBox.Text = dlg.FileName;
        }

        // TLS 인증서 검증 모드 콤보 선택이 바뀌면, 그 모드에 맞게 관련 UI(토글/텍스트박스)를 활성화/비활성화
        private void ClientTlsValidationModeCombo_SelectionChanged(
            object sender,
            SelectionChangedEventArgs e
        )
        {
            // 실제 UI 반영은 별도 함수로 분리
            ApplyTlsValidationModeUi();
        }

        // 선택된 TlsValidationMode에 따라 UI 입력 항목을 제어
        private void ApplyTlsValidationModeUi()
        {
            // 현재 선택된 모드 취득
            var mode = GetSelectedValidationMode();

            // 검증 모드 자체가 AllowUntrusted면 토글을 무조건 켜야 함
            if (mode == TlsValidationMode.AllowUntrusted)
            {
                ClientAllowUntrustedToggle.IsChecked = true;
                ClientAllowUntrustedToggle.IsEnabled = false;
            }
            else
            {
                ClientAllowUntrustedToggle.IsEnabled = true;
            }

            // CustomCa / Pinning 여부 계산
            var isCustomCa = mode == TlsValidationMode.CustomCa;
            var isPinning = mode == TlsValidationMode.ThumbprintPinning;

            // CA 경로 입력 제어
            // CustomCa 모드에서만 CA 경로 입력과 Browse 버튼 활성화
            if (ClientCaCertPathTextBox != null)
            {
                ClientCaCertPathTextBox.IsEnabled = isCustomCa;
                if (!isCustomCa)
                    ClientCaCertPathTextBox.Text = string.Empty;
            }

            ClientBrowseCaButton?.IsEnabled = isCustomCa;

            // Pinning 모드에서만 thumbprint 입력 가능
            if (ClientPinnedThumbprintTextBox != null)
            {
                ClientPinnedThumbprintTextBox.IsEnabled = isPinning;
                if (!isPinning)
                    ClientPinnedThumbprintTextBox.Text = string.Empty;
            }
        }

        // UI 입력값을 읽어서 AppSettings 객체를 만듬
        private AppSettings BuildSettingsFromUiPreserveSecrets()
        {
            // 토글이 체크되었을 때만 true
            var savePasswords = SavePasswordsToggle.IsChecked == true;

            // PasswordBox는 null 가능성이 있어 빈 문자열로 방어
            var brokerPasswordTyped = BrokerPfxPasswordBox.Password ?? string.Empty;
            var clientPasswordTyped = PublisherPassword.Password ?? string.Empty;

            // SavePasswords가 꺼져 있으면 null 유지
            string? brokerPasswordToSave = null;
            string? clientPasswordToSave = null;

            // SavePasswords ON인데 사용자가 PasswordBox를 비워두고 저장하면 실수로 비밀번호가 지워져 저장되는 문제를 막기 위해 기존값을 유지
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

            // ClientSettings 생성
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

            // ClientSettings 생성
            var broker = new BrokerSettings
            {
                Port = ParsePortOrThrow(BrokerPortTextBox.Text),
                PfxPath = BrokerPfxPathTextBox.Text?.Trim() ?? "cert\\devcert.pfx",
                PfxPassword = brokerPasswordToSave,
                SslProtocolsIndex = BrokerTlsProtocolCombo.SelectedIndex,
            };

            // 최종 AppSettings 반환
            return new AppSettings
            {
                SavePasswords = savePasswords,
                Client = client,
                Broker = broker,
            };
        }

        // AppSettings 값을 UI 컨트롤에 반영
        private void ApplySettingsToUi(AppSettings settings)
        {
            // SavePasswords 토글 반영
            SavePasswordsToggle.IsChecked = settings.SavePasswords;

            // Client 기본 항목 반영
            PublisherHost.Text = settings.Client.Host ?? "127.0.0.1";
            PublisherPort.Text = settings.Client.Port.ToString();
            PublisherClientID.Text = settings.Client.ClientId ?? string.Empty;
            PublisherUsername.Text = settings.Client.Username ?? string.Empty;

            // Client 비밀번호 반영
            PublisherPassword.Password = settings.SavePasswords
                ? (settings.Client.Password ?? string.Empty)
                : string.Empty;

            // TLS 토글 반영
            ClientUseTlsToggle.IsChecked = settings.Client.UseTls;
            ClientAllowUntrustedToggle.IsChecked = settings.Client.AllowUntrustedCertificates;

            // 콤보 인덱스는 ClampIndex로 처리
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

            // Custom CA / Thumbprint 값 반영
            ClientCaCertPathTextBox.Text = settings.Client.CaCertificatePath ?? string.Empty;
            ClientPinnedThumbprintTextBox.Text = settings.Client.PinnedThumbprint ?? string.Empty;

            // Subscribe / Publish 항목 반영
            SubTopicFilterTextBox.Text = settings.Client.SubTopicFilter ?? "info/#";
            SubQosCombo.SelectedIndex = ClampIndex(settings.Client.SubQosIndex, 0, 2);

            PubTopicTextBox.Text = settings.Client.PubTopic ?? "info/delta/sbms";
            PubPayloadTextBox.Text = settings.Client.PubPayload ?? string.Empty;
            PubQosCombo.SelectedIndex = ClampIndex(settings.Client.PubQosIndex, 0, 2);
            PubRetainToggle.IsChecked = settings.Client.PubRetain;

            // Broker 항목 반영 + 비밀번호 조건 반영
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

            // TLS 검증 모드에 맞춰 UI 정리
            ApplyTlsValidationModeUi();

            // 구독 목록 초기화
            _subscriptions.Clear();
        }

        // 포트 문자열을 int로 파싱하고, 1~65535 범위인지 검증
        private static int ParsePortOrThrow(string text)
        {
            // 숫자가 아니면 실패
            if (!int.TryParse(text?.Trim(), out var port))
                throw new InvalidOperationException("Port is not a number.");

            // TCP 포트 범위 벗어나면 실패
            if (port < 1 || port > 65535)
                throw new InvalidOperationException("Port is out of range.");

            return port;
        }

        // UI에서 ClientId가 비어 있으면 랜덤 ClientId를 생성
        private static string BuildClientId(string? uiValue)
        {
            // 사용자가 입력했으면 그대로 사용
            var cid = uiValue?.Trim();
            if (!string.IsNullOrWhiteSpace(cid))
                return cid;

            // 없으면 cli- + GUID 8자리로 생성
            return "cli-" + Guid.NewGuid().ToString("N")[..8];
        }

        // QoS 콤보박스 인덱스를 MQTT QoS enum으로 변환
        private static MqttQualityOfServiceLevel ParseQos(ComboBox combo)
        {
            // 0(기본) = QoS0
            // 1 = QoS1
            // 2 = QoS2
            return combo.SelectedIndex switch
            {
                1 => MqttQualityOfServiceLevel.AtLeastOnce,
                2 => MqttQualityOfServiceLevel.ExactlyOnce,
                _ => MqttQualityOfServiceLevel.AtMostOnce,
            };
        }

        // TLS 프로토콜 콤보 인덱스를 SslProtocols 플래그로 변환
        private static SslProtocols ParseSslProtocolsFromUi(ComboBox combo)
        {
            // 0: TLS 1.3
            // 1: TLS 1.2
            // 2: TLS 1.2 | 1.3(둘 다 허용)
            // 그 외: 기본 TLS 1.3
            return combo.SelectedIndex switch
            {
                0 => SslProtocols.Tls13,
                1 => SslProtocols.Tls12,
                2 => SslProtocols.Tls13 | SslProtocols.Tls12,
                _ => SslProtocols.Tls13,
            };
        }

        // 상대경로면 앱 실행 폴더 기준으로 절대경로로 변환
        // 이미 절대경로면 그대로 반환
        private static string ResolvePath(string path)
        {
            if (System.IO.Path.IsPathRooted(path))
                return path;

            return System.IO.Path.Combine(AppDomain.CurrentDomain.BaseDirectory, path);
        }

        // TLS 검증 모드 콤보 인덱스를 TlsValidationMode enum으로 변환
        private TlsValidationMode GetSelectedValidationMode()
        {
            //0: Strict
            // 1: AllowUntrusted
            // 2: CustomCa
            // 3: ThumbprintPinning
            // 그 외: Strict
            return ClientTlsValidationModeCombo.SelectedIndex switch
            {
                1 => TlsValidationMode.AllowUntrusted,
                2 => TlsValidationMode.CustomCa,
                3 => TlsValidationMode.ThumbprintPinning,
                _ => TlsValidationMode.Strict,
            };
        }

        // 콤보 인덱스가 범위를 벗어나면 안전한 값으로 보정
        private static int ClampIndex(int value, int min, int max)
        {
            if (value < min)
                return min;
            if (value > max)
                return max;
            return value;
        }
    }
}
