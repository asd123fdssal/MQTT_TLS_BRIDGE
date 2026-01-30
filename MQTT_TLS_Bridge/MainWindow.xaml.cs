using System.Collections.Concurrent;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using MQTT_TLS_Bridge.Broker;
using MQTT_TLS_Bridge.Control;
using MQTT_TLS_Bridge.Enums;
using MQTT_TLS_Bridge.Logging;
using MQTT_TLS_Bridge.Publisher;
using MQTT_TLS_Bridge.Settings;
using MQTTnet.Protocol;
using Wpf.Ui.Appearance;
using Wpf.Ui.Tray.Controls;

namespace MQTT_TLS_Bridge
{
    // MainWindow 클래스의 일부로 정의
    // Window를 상속
    public partial class MainWindow : Window
    {
        // MQTTnet 기반 브로커/클라이언트 기능 담당 서비스
        private readonly MqttBrokerService _brokerService = new();
        private readonly MqttPublisherService _publisherService = new();

        // 앱 전체 Lifecycle 취소 토큰
        private readonly CancellationTokenSource _cts = new();

        // ListBox에 바인딩되는 표시용 토픽 목록
        // 리스트가 바뀌면(UI에 보여주는 데이터가 바뀌면) 화면이 자동으로 갱신되도록 이벤트를 내주는 컬렉션
        private readonly ObservableCollection<string> _brokerTopics = [];

        // 멀티스레드에서 안전하게 쓰는 Dictionary
        // 여러 스레드가 동시에 읽고/쓰더라도 데이터 깨짐 없이 동작하도록 설계된 해시맵
        private readonly ConcurrentDictionary<string, string> _brokerLastByTopic = new(
            StringComparer.Ordinal
        );

        // 토픽별 마지막 payload 저장
        private readonly ObservableCollection<string> _clientTopics = [];
        private readonly ConcurrentDictionary<string, string> _clientLastByTopic = new(
            StringComparer.Ordinal
        );

        // 구독 목록 표시/선택용
        private readonly ObservableCollection<SubscriptionEntry> _subscriptions = [];

        // 백그라운드 스레드에서 UI 안전 접근을 위해 Dispatcher.InvokeAsync 래핑
        // UI 스레드에서 실행해야 하는 코드를 await 가능한 Task로 실행시키는 헬퍼
        // WPF는 UI 컨트롤을 UI 스레드에서만 접근 가능
        // Dispatcher.InvokeAsync()는 UI 스레드 큐에 작업을 넣고 실행
        // Task를 반환하니 바깥에서 await UiAsync()가 가능
        private Task<T> UiAsync<T>(Func<T> func) => Dispatcher.InvokeAsync(func).Task;

        private Task UiAsync(Action action) => Dispatcher.InvokeAsync(action).Task;

        // INI Control Server 인스턴스와 동시성 제어
        // 명령 처리 락, Lifecycle 락
        private IniControlServer? _controlServer;

        // SemaphoreSlim은 동시에 실행될 수 있는 작업(코드 구간)의 개수를 제한하는 비동기용 세마포어(잠금 장치)
        // async/await 환경에서 쓰는 락(lock) 대용으로 많이 씀
        // 초기 허용 수 = 1, 최대 허용 수 = 1, Mutex, Lock과 유사함
        private readonly SemaphoreSlim _controlLock = new(1, 1);
        private readonly SemaphoreSlim _serverLifecycleLock = new(1, 1);

        // 세팅 값
        private AppSettings? _lastLoadedSettings;

        // UI 로깅 관련
        private const int MaxLogLines = 200;
        private const int TrimLogLines = 100;
        private const int MaxServerLogLines = 300;
        private const int TrimServerLogLines = 150;

        private const string ErrBadRequest = "BadRequest";
        private const string LogServerName = "Server";

        // 로그 파일 생성 관련
        private readonly DailyFileLogger _fileLog = new(
            System.IO.Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "Logs")
        );

        // 이벤트
        private Action<string, string>? _onRawReceived;
        private Action<string, string>? _onRawSent;

        private Action<string>? _onCtrlClientConnected;
        private Action<string>? _onCtrlClientDisconnected;

        private Action<string, string, string>? _onPacketReceived;
        private Action<string, string, bool>? _onPacketSent;

        // INI Control Server 포트
        private const int DefaultControlPort = 4811;

        // 닫기 버튼 눌러도 트레이로 숨김 / 진짜 종료 구분
        private bool _exitRequested;
        private bool _isShuttingDown;

        // 생성자
        public MainWindow()
        {
            // XAML 로드 + 컨트롤 생성
            InitializeComponent();

            // 앱 테마를 다크로 적용(Wpf.Ui)
            ApplicationThemeManager.Apply(ApplicationTheme.Dark);

            // ListBox에 ObservableCollection을 연결
            TopicListBox.ItemsSource = _brokerTopics;
            ClientTopicListBox.ItemsSource = _clientTopics;
            SubscribedTopicListBox.ItemsSource = _subscriptions;

            // 브로커 서비스 로그/메시지 수신 이벤트 연결
            _brokerService.Log += AppendBrokerLog;
            _brokerService.MessageReceived += OnBrokerMessageReceived;

            // 클라이언트(퍼블리셔) 서비스 로그/메시지 수신 이벤트 연결
            _publisherService.Log += AppendClientLog;
            _publisherService.MessageReceived += OnClientMessageReceived;

            _publisherService.ConnectionStateChanged += PublisherService_ConnectionStateChanged;
        }

        // 퍼블리셔 연결 상태(Disconnected/Connecting/Connected/Error)가 바뀌면 UI의 상태 텍스트/LED 색을 업데이트
        private void PublisherService_ConnectionStateChanged(ConnectionState state, string? detail)
        {
            // 이벤트는 다른 스레드에서 올 수 있으니 UI 업데이트를 Dispatcher로 감쌈
            Dispatcher.Invoke(() =>
            {
                // 상태 텍스트 표시
                ConnStatusText.Text = state.ToString();

                // 상태별 LED 색 지정
                ConnLed.Fill = state switch
                {
                    // Connected
                    ConnectionState.Connected => new SolidColorBrush(
                        Color.FromRgb(0x2E, 0xCC, 0x71)
                    ),
                    // Connecting
                    ConnectionState.Connecting => new SolidColorBrush(
                        Color.FromRgb(0xF1, 0xC4, 0x0F)
                    ),
                    // Disconnected
                    ConnectionState.Error => new SolidColorBrush(Color.FromRgb(0xE7, 0x4C, 0x3C)),
                    _ => new SolidColorBrush(Color.FromRgb(0xEC, 0x2B, 0x13)),
                };

                // 에러 상세 메시지가 있으면 클라이언트 로그에도 남김
                if (state == ConnectionState.Error && !string.IsNullOrWhiteSpace(detail))
                    AppendClientLog($"Client error: {detail}");
            });
        }

        // 창 로드 시 TLS UI 초기화, 설정 파일 로드/적용, Control Server 기본값 세팅, 트레이 등록, 서버 토글 ON
        private async void Window_Loaded(object sender, RoutedEventArgs e)
        {
            try
            {
                // TLS 검증 모드 콤보 기본값 보정 + UI 활성/비활성 동기화
                if (ClientTlsValidationModeCombo.SelectedIndex < 0)
                    ClientTlsValidationModeCombo.SelectedIndex = 0;

                ApplyTlsValidationModeUi();

                // settings.json 있으면 로드해서 UI에 반영
                if (SettingsStore.Exists())
                {
                    _lastLoadedSettings = SettingsStore.Load();
                    ApplySettingsToUi(_lastLoadedSettings);
                    AppendClientLog("Settings loaded.");
                }

                // Control Server 기본 포트 4811
                // 외부 접속 기본 OFF
                // 토글을 true로 만들어 서버 자동 시작
                ServerPortTextBox.Text = DefaultControlPort.ToString();

                ServerAllowRemoteCheckBox.IsChecked = false;
                ServerToggle.IsChecked = true;
                // 트레이 아이콘 등록
                AppTrayIcon.Register();
            }
            catch (Exception ex)
            {
                // 에러 로깅
                AppendClientLog($"Load on start failed: {ex.GetType().Name}: {ex.Message}");
            }
        }

        // 창 닫기 시 트레이로 숨김과 진짜 종료를 구분해서 처리
        private void Window_Closing(object sender, CancelEventArgs e)
        {
            // 이미 종료 프로세스 중이면 중복 방지
            if (_isShuttingDown)
                return;

            // 사용자가 Exit를 누르지 않았다면
            if (!_exitRequested)
            {
                // 닫기 버튼(X)은 종료가 아니라 숨김
                // Close 이벤트 취소 후 Hide
                e.Cancel = true;
                Hide();
                return;
            }

            // 진짜 종료
            // 이벤트 해제
            _publisherService.ConnectionStateChanged -= PublisherService_ConnectionStateChanged;

            // 닫기 이벤트는 일단 취소
            _isShuttingDown = true;
            e.Cancel = true;

            // 백그라운드로 ShutdownAsync() 실행
            _ = ShutdownAsync();
        }

        // 프로그램 종료 시: Control Server 중지 → 앱 CTS 취소 → MQTT 서비스 Dispose → CTS Dispose
        //                  → Application.Shutdown → 파일로거/트레이 정리
        private async Task ShutdownAsync()
        {
            try
            {
                // Control server부터 내리고
                // 전체 취소 토큰 cancel
                // 퍼블리셔 / 브로커 dispose(내부 stop 포함)

                await StopControlServerAsync().ConfigureAwait(false);
                await _cts.CancelAsync().ConfigureAwait(false);

                await _publisherService.DisposeAsync().ConfigureAwait(false);
                await _brokerService.DisposeAsync().ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                // 에러 메시지 로깅
                AppendClientLog($"Shutdown error: {ex.GetType().Name}: {ex.Message}");
            }
            finally
            {
                try
                {
                    // 취소 토큰 Dispose()
                    _cts.Dispose();
                }
                catch (Exception ex)
                {
                    // 에러 메시지 로깅
                    AppendClientLog($"CTS dispose error: {ex.GetType().Name}: {ex.Message}");
                }

                try
                {
                    // UI 스레드에서 Application 종료 호출
                    await Dispatcher.InvokeAsync(() =>
                    {
                        try
                        {
                            // WPF 종료는 UI 스레드가 안전
                            Application.Current.Shutdown();
                        }
                        catch (Exception ex)
                        {
                            // 에러 메시지 로깅
                            AppendClientLog(
                                $"Application shutdown error: {ex.GetType().Name}: {ex.Message}"
                            );
                        }
                    });
                }
                catch (Exception ex)
                {
                    // 에러 메시지 로깅
                    AppendClientLog($"Dispatcher error: {ex.GetType().Name}: {ex.Message}");
                }

                try
                {
                    // 파일 로거 Dispose()
                    // 실패해도 종료 흐름 방해하지 않게 catch 처리
                    await _fileLog.DisposeAsync().ConfigureAwait(false);
                }
                catch (Exception ex)
                {
                    // 종료 단계에서 파일 로그 정리 실패는 복구 불가이며 앱 종료 흐름을 방해하지 않기 위해 무시
                    AppendClientLog($"FileLog dispose error: {ex.GetType().Name}: {ex.Message}");
                }
                try
                {
                    //  UI 스레드에서 트레이 해제
                    await Dispatcher.InvokeAsync(() =>
                    {
                        try
                        {
                            // 트레이 해제
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

        // Exit 버튼을 누르면 창을 닫음
        // 단, 실제 종료 여부는 Window_Closing에서 _exitRequested에 따라 결정
        private void ExitButton_Click(object sender, RoutedEventArgs e) => Close();

        // UI에서 Broker 토글 ON시 내장 MQTTS 브로커를 시작
        private async void BrokerToggle_Checked(object sender, RoutedEventArgs e)
        {
            try
            {
                // 포트 숫자/범위 검증
                var port = ParsePortOrThrow(BrokerPortTextBox.Text);

                // PFX 경로 필수
                // 상대 경로면 앱 폴더 기준 절대 경로로 변환
                var pfxPath = (BrokerPfxPathTextBox.Text ?? string.Empty).Trim();
                if (string.IsNullOrWhiteSpace(pfxPath))
                    throw new InvalidOperationException("PFX path is empty.");

                pfxPath = ResolvePath(pfxPath);

                // TLS 설정 + 인증서로 브로커 시작
                var password = BrokerPfxPasswordBox.Password ?? string.Empty;
                var ssl = ParseSslProtocolsFromUi(BrokerTlsProtocolCombo);

                await _brokerService.StartAsync(pfxPath, password, port, ssl, _cts.Token);
                AppendBrokerLog("Broker started.");
            }
            catch (Exception ex)
            {
                // 실패하면 토글을 다시 OFF로 되돌림(상태 불일치 방지)
                AppendBrokerLog($"Broker start failed: {ex.GetType().Name}: {ex.Message}");
                BrokerToggle.IsChecked = false;
            }
        }

        // UI에서 Broker 토글 OFF 시 브로커를 중지
        private async void BrokerToggle_Unchecked(object sender, RoutedEventArgs e)
        {
            try
            {
                // 브로커 종료 요청(취소 토큰 포함)
                await _brokerService.StopAsync(_cts.Token);
                AppendBrokerLog("Broker stopped.");
            }
            catch (Exception ex)
            {
                // 에러 메시지 로깅
                AppendBrokerLog($"Broker stop failed: {ex.GetType().Name}: {ex.Message}");
            }
        }

        // UI에서 Client Connect 토글 ON 시 MQTT 클라이언트 연결 설정을 만들어 Connect
        private async void PublisherConnect_Checked(object sender, RoutedEventArgs e)
        {
            try
            {
                // Host/Port/ClientId 필수
                // Username / Password 선택
                // TLS 여부 및 인증서 검증 모드도 반영
                var settings = new PublisherConnectionSettings
                {
                    Host = PublisherHost.Text?.Trim() ?? string.Empty,
                    Port = ParsePortOrThrow(PublisherPort.Text),
                    ClientId = BuildClientId(PublisherClientID.Text), // UI에 없으면 자동 생성(cli-xxxxxxxx)
                    Username = string.IsNullOrWhiteSpace(PublisherUsername.Text)
                        ? null
                        : PublisherUsername.Text.Trim(),
                    Password = PublisherPassword.Password,
                    UseTls = ClientUseTlsToggle.IsChecked == true,
                    AllowUntrustedCertificates = ClientAllowUntrustedToggle.IsChecked == true,
                    SslProtocols = ParseSslProtocolsFromUi(ClientTlsProtocolCombo),
                    ValidationMode = GetSelectedValidationMode(), // TLS 검증 모드에 따라 CA 경로나 핀닝 지문이 사용될 수 있음
                    CaCertificatePath = string.IsNullOrWhiteSpace(ClientCaCertPathTextBox.Text)
                        ? null
                        : ResolvePath(ClientCaCertPathTextBox.Text.Trim()),
                    PinnedThumbprint = string.IsNullOrWhiteSpace(ClientPinnedThumbprintTextBox.Text)
                        ? null
                        : ClientPinnedThumbprintTextBox.Text.Trim(),
                };

                // 연결
                await _publisherService.ConnectAsync(settings, _cts.Token);
            }
            catch (Exception ex)
            {
                // 실패하면 에러 메시지 로깅 후 토글을 OFF로 되돌림
                AppendClientLog($"Client connect failed: {ex.GetType().Name}: {ex.Message}");
                PublisherConnect.IsChecked = false;
            }
        }

        // UI에서 Client Connect 토글 OFF 시 MQTT 연결을 끊음
        private async void PublisherConnect_Unchecked(object sender, RoutedEventArgs e)
        {
            try
            {
                // 현재 연결이 있으면 끊고 상태 갱신은 서비스 이벤트로 반영
                await _publisherService.DisconnectAsync(_cts.Token);
            }
            catch (Exception ex)
            {
                // 에러 메시지 로깅
                AppendClientLog($"Client disconnect failed: {ex.GetType().Name}: {ex.Message}");
            }
        }

        // 입력한 Topic Filter로 Subscribe 수행 + UI 구독 목록 갱신 + 로그 출력
        private async void SubscribeButton_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                // filter 필수
                var filter = (SubTopicFilterTextBox.Text ?? string.Empty).Trim();
                if (string.IsNullOrWhiteSpace(filter))
                    throw new InvalidOperationException("Topic filter is empty.");

                // QoS 선택값을 enum으로 변환 후 subscribe 호출
                var qos = ParseQos(SubQosCombo);

                await _publisherService.SubscribeAsync(filter, qos, _cts.Token);

                // UI 목록 업데이트(있으면 갱신, 없으면 추가)
                UpsertSubscription(filter, qos);
                AppendClientLog($"Subscribed: {filter} (QoS {(int)qos})");
            }
            catch (Exception ex)
            {
                // 에러 메시지 로깅
                AppendClientLog($"Subscribe failed: {ex.GetType().Name}: {ex.Message}");
            }
        }

        // 입력한 Topic Filter로 Unsubscribe 수행 + UI 목록에서 제거 + 로그 출력
        private async void UnsubscribeButton_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                // filter 필수
                var filter = (SubTopicFilterTextBox.Text ?? string.Empty).Trim();
                if (string.IsNullOrWhiteSpace(filter))
                    throw new InvalidOperationException("Topic filter is empty.");

                // Unsubscribe 호출
                await _publisherService.UnsubscribeAsync(filter, _cts.Token);

                // UI 목록 업데이트
                RemoveSubscription(filter);
                AppendClientLog($"Unsubscribed: {filter}");
            }
            catch (Exception ex)
            {
                // 에러 메시지 출력
                AppendClientLog($"Unsubscribe failed: {ex.GetType().Name}: {ex.Message}");
            }
        }

        // 구독 목록에서 항목을 클릭하면 해당 항목의 filter/QoS를 입력 UI에 자동으로 채움
        private void SubscribedTopicListBox_SelectionChanged(
            object sender,
            SelectionChangedEventArgs e
        )
        {
            // 미 선택시 종료
            if (SubscribedTopicListBox.SelectedItem is not SubscriptionEntry entry)
                return;

            SubTopicFilterTextBox.Text = entry.TopicFilter;

            // QoS enum을 콤보 index로 역변환
            SubQosCombo.SelectedIndex = entry.Qos switch
            {
                MqttQualityOfServiceLevel.AtLeastOnce => 1,
                MqttQualityOfServiceLevel.ExactlyOnce => 2,
                _ => 0,
            };
        }

        // Topic + Payload + QoS + Retain 값을 읽어서 Publish 수행
        private async void PublishButton_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                // topic 필수
                var topic = (PubTopicTextBox.Text ?? string.Empty).Trim();
                if (string.IsNullOrWhiteSpace(topic))
                    throw new InvalidOperationException("Topic is empty.");

                var payload = PubPayloadTextBox.Text ?? string.Empty;
                var qos = ParseQos(PubQosCombo);
                var retain = PubRetainToggle.IsChecked == true;

                // Publish
                await _publisherService.PublishAsync(topic, payload, retain, qos, _cts.Token);
            }
            catch (Exception ex)
            {
                // 에러 메시지 로깅
                AppendClientLog($"Publish failed: {ex.GetType().Name}: {ex.Message}");
            }
        }

        // 서버 로그 텍스트박스를 비우고 지웠다는 로그를 남김
        private void ClearServerLogButton_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                ServerLogTextBox.Clear();
                // 성공 메시지 로깅
                AppendServerLog("Server log cleared.");
            }
            catch (Exception ex)
            {
                // 에러 메시지 로깅
                AppendClientLog($"Clear server log failed: {ex.GetType().Name}: {ex.Message}");
            }
        }

        // 클라이언트 수신 토픽 히스토리(목록/마지막 payload)를 모두 초기화
        private void ClearClientTopicsButton_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                _clientTopics.Clear();
                _clientLastByTopic.Clear();
                ClientTopicListBox.SelectedItem = null;
                ClientLastMessageTextBox.Text = string.Empty;
                // 성공 메시지 로깅
                AppendClientLog("Client topic history cleared.");
            }
            catch (Exception ex)
            {
                // 에러 메시지 로깅
                AppendClientLog($"Clear client topics failed: {ex.GetType().Name}: {ex.Message}");
            }
        }

        // 브로커 수신 토픽 히스토리 초기화(목록/마지막 payload/선택/표시 텍스트)
        private void ClearBrokerTopicsButton_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                _brokerTopics.Clear();
                _brokerLastByTopic.Clear();
                TopicListBox.SelectedItem = null;
                BrokerDataTextBox.Text = string.Empty;
                // 성공 메시지 로깅
                AppendBrokerLog("Broker topic history cleared.");
            }
            catch (Exception ex)
            {
                // 에러 메시지 로깅
                AppendBrokerLog($"Clear broker topics failed: {ex.GetType().Name}: {ex.Message}");
            }
        }

        // 구독 목록을 UI에서 모두 지움(실제 unsubscribe를 호출하는 건 아님)
        private void ClearSubscribedTopicsButton_Click(object sender, RoutedEventArgs e)
        {
            // _subscriptions.Clear()는 UI 표시/내부 리스트만 초기화
            _subscriptions.Clear();
            SubscribedTopicListBox.SelectedItem = null;
            // 성공 메시지 로깅
            AppendClientLog("Subscribed topics cleared.");
        }

        // 같은 filter가 있으면 QoS를 업데이트하고, 없으면 새 항목을 추가
        private void UpsertSubscription(string filter, MqttQualityOfServiceLevel qos)
        {
            // for로 선형 탐색 → 있으면 교체(_subscriptions[i] = new ...) → 반환
            // 없으면 _subscriptions.Add(...)
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

        // 같은 filter가 있으면 목록에서 제거
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

        // 구독 항목 데이터 모델(TopicFilter + QoS)
        // ListBox에 표시될 텍스트는 ToString() 결과를 사용
        private sealed record SubscriptionEntry(string TopicFilter, MqttQualityOfServiceLevel Qos)
        {
            public override string ToString() => $"{TopicFilter} (QoS {(int)Qos})";
        }

        // 트레이에서 더블클릭 시 창을 다시 보여줌
        private void AppTrayIcon_LeftDoubleClick(NotifyIcon sender, RoutedEventArgs e)
        {
            RestoreFromTray();
        }

        // 트레이에서 열기 클릭 시 창을 다시 보여줌
        private void TrayOpen_Click(object sender, RoutedEventArgs e)
        {
            RestoreFromTray();
        }

        // 트레이의 Exit 클릭 시 진짜 종료 플래그를 세우고 Close()를 호출
        private void TrayExit_Click(object sender, RoutedEventArgs e)
        {
            _exitRequested = true;
            Close();
        }

        // 숨겨진 창을 다시 표시하고 포커스를 확실히 가져오도록 처리
        private void RestoreFromTray()
        {
            Show();
            WindowState = WindowState.Normal;
            Activate();
            // Topmost를 잠깐 켰다 끄는 건 다른 창 뒤에 숨어있는 문제를 피하려는 트릭으로 사용
            Topmost = true;
            Topmost = false;
            Focus();
        }
    }
}
