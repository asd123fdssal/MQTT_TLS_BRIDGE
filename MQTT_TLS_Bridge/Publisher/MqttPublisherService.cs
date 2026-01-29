using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
using MQTT_TLS_Bridge.Enums;
using MQTT_TLS_Bridge.Utils;
using MQTTnet;
using MQTTnet.Protocol;

namespace MQTT_TLS_Bridge.Publisher
{
    // 인스턴스화 할수 있으나, 상속은 불가한 클래스
    // IAsyncDisposable를 구현(implement)하여 비동기적으로 리소스를 해제하는 기능을 제공
    public sealed class MqttPublisherService : IAsyncDisposable
    {
        // nullable IMqttClient(Interface) 타입의 필드 _client 선언
        private IMqttClient? _client;

        // [Delegate, Action, Func]의 차이점
        // Deletegate: 메서드 참조를 저장할 수 있는 형식 (메서드 시그니처와 일치하는 모든 메서드를 참조할 수 있음)
        //             항상 마지막에 동작한 메서드의 값이 반환됨
        //             의미 있는 이름을 붙여 콜백의 의도를 타입으로 표현할 수 있음
        //             외부에 노출되는 API, 의미가 중요한 이벤트 핸들러 타입 정의에 자주 사용

        // Action: 반환 값이 없는 메서드를 참조하는 데 사용 (0~16개의 매개변수를 가질 수 있음)
        //         Action<T1, T2, ...> 형태로 사용하며 마지막까지 모두 입력 매개변수
        //         이벤트, 알림, 로그처럼 결과값이 필요 없는 콜백에 주로 사용

        // Func: 반환 값이 있는 메서드를 참조하는 데 사용 (0~16개의 매개변수를 가질 수 있음)
        //       항상 마지막에 동작한 메서드의 값이 반환됨
        //       Func<T1, T2, ..., TResult> 형태로 사용하며 마지막 타입이 반환값
        //       계산, 변환, 조건 판정(필터), 정렬 기준 같은 로직 전달에 주로 사용

        // Task: 비동기 작업의 진행 중인 상태를 담는 객체
        // await을 사용하기 위해서는 Task 계열의 타입을 반환해야 함

        // MqttClientConnectedEventArgs 등의 이벤트를 입력으로 받고 Task를 반환하는 Func 필드 선언
        private Func<MqttClientConnectedEventArgs, Task>? _onConnected;
        private Func<MqttClientDisconnectedEventArgs, Task>? _onDisconnected;
        private Func<MqttApplicationMessageReceivedEventArgs, Task>? _onMessageReceived;

        // 읽기 전용 속성 IsConnected 선언
        public bool IsConnected => _client?.IsConnected == true;

        // 이벤트 선언
        public event Action<string>? Log;
        public event Action<ConnectionState, string?>? ConnectionStateChanged;
        public event Action<PublisherMessage>? MessageReceived;

        // 비동기 메서드 ConnectAsync 선언
        // 퍼블리셔 MQTT 클라이언트를 설정값으로 생성하고 이벤트를 등록한 뒤 브로커에 연결함
        public async Task ConnectAsync(
            PublisherConnectionSettings settings,
            CancellationToken cancellationToken
        )
        {
            // 호출 시점에 이미 취소 상태면 예외를 던져 연결을 시작하지 않음
            cancellationToken.ThrowIfCancellationRequested();

            // 이미 연결되어 있으면 다시 연결하지 않음
            if (IsConnected)
            {
                WriteLog("Client already connected.");
                return;
            }

            // UI나 내부 로직이 연결 진행 중임을 알 수 있게 상태를 갱신함
            SetState(ConnectionState.Connecting, null);

            // 이전 연결 시도 실패나 남아 있는 리소스를 정리함
            ResetClient();

            // 새 MQTT 클라이언트 인스턴스를 만듦
            _client = CreateClient();
            // 연결, 해제, 메시지 수신 같은 이벤트 핸들러를 등록함
            RegisterClientEventHandlers(_client);

            // Host, Port, ClientId, TLS 설정, 인증서 검증 모드 같은 설정을 기반으로 접속 옵션을 만듦
            var options = BuildOptions(settings);

            // 네트워크 연결과 MQTT CONNECT 핸드셰이크를 수행함
            await DoConnectAsync(_client, options, cancellationToken);

            // UI 연결 상태를 갱신
            SetState(ConnectionState.Connected, null);
            // 성공 로그를 남김
            WriteLog("Client connected.");
        }

        // 비동기 메서드 DisconnectAsync 선언
        // MQTT 클라이언트가 존재하고 연결되어 있으면 비동기로 연결을 끊음
        public async Task DisconnectAsync(CancellationToken cancellationToken)
        {
            // 이미 정리된 상태거나 아직 연결을 만든 적이 없을 수 있음
            // 이 경우 끊을 대상이 없으므로 Disconnected로 상태를 확정하고 종료
            if (_client == null)
            {
                SetState(ConnectionState.Disconnected, null);
                return;
            }

            // 연결된 경우에만 Disconnect를 호출
            try
            {
                if (_client.IsConnected)
                    await _client.DisconnectAsync(cancellationToken: cancellationToken);
            }
            finally
            {
                // Disconnect가 성공하든 실패하든, 예외가 나든 상관없이 실행
                // 내부 상태와 UI를 항상 Disconnected로 맞춤
                SetState(ConnectionState.Disconnected, null);
                WriteLog("Client disconnected.");
            }
        }

        // 비동기 메서드 PublishAsync 선언
        // 현재 MQTT 클라이언트가 연결된 상태인지 확인한 뒤 지정한 토픽으로 메시지를 발행
        public async Task PublishAsync(
            string topic, // 메시지를 발행할 토픽
            string payloadText, // 메시지 페이로드(내용)
            bool retain, // 메시지를 브로커에 유지할지 여부
            MqttQualityOfServiceLevel qos, // 메시지의 QoS 수준
            CancellationToken cancellationToken // 작업 취소 토큰
        )
        {
            // 클라이언트가 null이거나 연결되지 않았으면 예외를 던져서 발행을 막음
            EnsureConnected();

            var msg = new MqttApplicationMessageBuilder() // 메시지 조립을 위한 빌더를 만듦
                .WithTopic(topic) // 발행할 MQTT 토픽을 설정
                .WithPayload(payloadText ?? string.Empty) // 페이로드를 문자열로 설정한다 payloadText가 null이면 빈 문자열로 대체
                .WithRetainFlag(retain) // retain 플래그 설정, true면 브로커가 마지막 메시지를 저장해 두었다가 새 구독자에게 즉시 전달할 수 있음
                .WithQualityOfServiceLevel(qos) // 전달 보장 수준을 결정
                .Build(); // 최종 메시지 객체를 만듦

            // 클라이언트를 통해 비동기로 메시지를 발행
            await _client!.PublishAsync(msg, cancellationToken);
            // 어떤 토픽으로 어떤 옵션(QoS, retain)으로 발행했는지 기록
            WriteLog($"Published: Topic={topic}, QoS={qos}, Retain={retain}");
        }

        // 비동기 메서드 SubscribeAsync 선언
        // 연결된 MQTT 클라이언트로 지정한 토픽을 구독한다
        public async Task SubscribeAsync(
            string topic, // 구독할 토픽
            MqttQualityOfServiceLevel qos, // 구독할 메시지의 QoS 수준
            CancellationToken cancellationToken // 작업 취소 토큰
        )
        {
            // 클라이언트가 null이거나 연결되지 않았으면 예외를 던져서 구독을 막음
            EnsureConnected();

            var filter = new MqttTopicFilterBuilder() // 토픽 필터 빌더를 만듦
                .WithTopic(topic) // 구독할 토픽을 설정
                .WithQualityOfServiceLevel(qos) // QoS 수준을 설정
                .Build(); // 최종 토픽 필터 객체를 만듦

            // 실제 구독을 수행
            await _client!.SubscribeAsync(filter, cancellationToken);
            // 어떤 토픽을 어떤 QoS로 구독했는지 기록
            WriteLog($"Subscribed: {topic} (QoS={qos})");
        }

        // 비동기 메서드 UnsubscribeAsync 선언
        // 연결된 MQTT 클라이언트로 지정한 토픽 필터 구독을 해제한다
        public async Task UnsubscribeAsync(string topicFilter, CancellationToken cancellationToken)
        {
            // 클라이언트가 null이거나 연결되지 않았으면 예외를 던져서 구독 해제를 막음
            EnsureConnected();

            // topicFilter가 null 또는 공백이면 InvalidOperationException을 던진다
            if (string.IsNullOrWhiteSpace(topicFilter))
                throw new InvalidOperationException("Topic filter is empty.");

            // 실제 구독 해제를 수행
            await _client!.UnsubscribeAsync(topicFilter, cancellationToken);
            // 어떤 토픽 필터의 구독을 해제했는지 기록
            WriteLog($"Unsubscribed: {topicFilter}");
        }

        // 비동기 메서드 DisposeAsync 선언
        // 퍼블리셔 클라이언트를 안전하게 종료하고 리소스를 해제
        public async ValueTask DisposeAsync()
        {
            // 정리할 대상이 없으므로 바로 종료
            if (_client == null)
                return;

            try
            {
                // 연결된 상태면 _client.DisconnectAsync()로 정상 종료를 시도
                if (_client.IsConnected)
                    await _client.DisconnectAsync();
            }
            finally
            {
                // 이벤트 핸들러 해제
                UnregisterClientEventHandlers(_client);
                // 클라이언트 Dispose
                _client.Dispose();
                // _client = null로 상태를 확정
                _client = null;
            }
        }

        // 정적 메서드 CreateClient 선언
        // MQTTnet 팩토리로 새 MQTT 클라이언트 인스턴스를 생성
        private static IMqttClient CreateClient()
        {
            // MqttClientFactory를 만들고 CreateMqttClient()로 IMqttClient를 반환
            var factory = new MqttClientFactory();
            return factory.CreateMqttClient();
        }

        // 인스턴스 메서드 ResetClient 선언
        // 기존 클라이언트가 남아있으면 이벤트를 해제하고 Dispose하여 초기화
        private void ResetClient()
        {
            // _client == null이면 아무 것도 하지 않는다
            if (_client == null)
                return;

            try
            {
                // 이벤트 해제 후 Dispose한다
                UnregisterClientEventHandlers(_client);
                _client.Dispose();
            }
            finally
            {
                // _client = null로 상태를 확정
                _client = null;
            }
        }

        // 정적 메서드 BuildOptions 선언
        // PublisherConnectionSettings를 기반으로 MQTT 접속 옵션을 생성
        private static MqttClientOptions BuildOptions(PublisherConnectionSettings settings)
        {
            // 검증 모드를 결정한다
            var validationMode = ResolveValidationMode(settings);

            // TLS 기본 옵션을 구성한다
            var tlsBuilder = new MqttClientTlsOptionsBuilder()
                .UseTls(settings.UseTls) // TLS 사용 여부 설정
                .WithSslProtocols(settings.SslProtocols); // 허용할 SSL/TLS 프로토콜 설정 (예: TLS 1.2, TLS 1.3)

            // 검증 모드에 따라 인증서 검증 핸들러를 다르게 설정한다
            if (validationMode == TlsValidationMode.AllowUntrusted) // 신뢰할 수 없는 인증서 허용 모드
            {
                tlsBuilder = tlsBuilder
                    .WithAllowUntrustedCertificates(true) // 신뢰할 수 없는 인증서 허용
                    .WithIgnoreCertificateChainErrors(true) // 인증서 체인 오류 무시
                    .WithIgnoreCertificateRevocationErrors(true) // 인증서 폐기 오류 무시
                    .WithCertificateValidationHandler(_ => true); // 모든 인증서를 유효한 것으로 간주
            }
            else if (validationMode != TlsValidationMode.Strict) // Strict 모드가 아닌 경우 (CustomCa, ThumbprintPinning)
            {
                tlsBuilder = tlsBuilder.WithCertificateValidationHandler(ctx =>
                    ValidateServerCertificate(ctx, settings, validationMode) // Strict가 아니면 커스텀 검증 콜백으로 ValidateServerCertificate를 사용
                );
            }

            // TLS 옵션을 Build
            var tls = tlsBuilder.Build();

            // MQTT 접속 옵션을 구성
            var optionsBuilder = new MqttClientOptionsBuilder()
                .WithTcpServer(settings.Host, settings.Port) // 브로커 호스트와 포트 설정
                .WithClientId(settings.ClientId) // 클라이언트 ID 설정
                .WithTlsOptions(tls); // TLS 옵션 설정

            // Username이 있으면 WithCredentials로 사용자 인증을 추가
            if (!string.IsNullOrWhiteSpace(settings.Username))
                optionsBuilder = optionsBuilder.WithCredentials(
                    settings.Username, // 사용자 이름
                    settings.Password // 비밀번호
                );

            // Build로 옵션을 반환
            return optionsBuilder.Build();
        }

        // 정적 메서드 ResolveValidationMode 선언
        // 설정값을 기준으로 실제 TLS 인증서 검증 모드를 결정
        private static TlsValidationMode ResolveValidationMode(PublisherConnectionSettings settings)
        {
            // settings.ValidationMode가 Strict가 아니면 그대로 반환
            if (settings.ValidationMode != TlsValidationMode.Strict)
                return settings.ValidationMode;

            // AllowUntrustedCertificates 플래그에 따라 Strict 또는 AllowUntrusted를 반환
            return settings.AllowUntrustedCertificates
                ? TlsValidationMode.AllowUntrusted
                : TlsValidationMode.Strict;
        }

        // 정적 메서드 ValidateServerCertificate 선언
        // TLS 인증서 검증 모드에 따라 서버 인증서를 검증
        private static bool ValidateServerCertificate(
            MqttClientCertificateValidationEventArgs context, // 인증서 검증 컨텍스트
            PublisherConnectionSettings settings, // 퍼블리셔 연결 설정
            TlsValidationMode mode // TLS 검증 모드
        )
        {
            // Strict면 SslPolicyErrors.None일 때만 true를 반환
            if (mode == TlsValidationMode.Strict)
                return context.SslPolicyErrors == SslPolicyErrors.None;

            // 인증서가 없으면 false를 반환
            if (context.Certificate == null)
                return false;

            // 인증서를 X509Certificate2로 감싸서 모드별 검증 함수로 분기
            using var cert = new X509Certificate2(context.Certificate);

            return mode switch
            {
                TlsValidationMode.CustomCa => ValidateWithCustomCa(settings, cert), // CustomCa는 지정한 CA로 체인 검증
                TlsValidationMode.ThumbprintPinning => ValidateWithThumbprint(settings, cert), // ThumbprintPinning은 지문 일치 여부 확인
                _ => false,
            };
        }

        // 정적 메서드 ValidateWithCustomCa 선언
        // 지정된 CA 인증서를 신뢰 루트로 사용하여 서버 인증서 체인을 검증
        private static bool ValidateWithCustomCa(
            PublisherConnectionSettings settings, // 퍼블리셔 연결 설정
            X509Certificate2 cert // 서버 인증서
        )
        {
            // CA 인증서 경로가 비어 있으면 false 반환
            if (string.IsNullOrWhiteSpace(settings.CaCertificatePath))
                return false;

            try
            {
                // CA 인증서를 로드하고 X509Chain을 생성
                using var caCert = CertUtil.LoadCertificateFromFile(settings.CaCertificatePath);
                using var chain = new X509Chain();

                // ChainPolicy를 CustomRootTrust로 설정하고 CustomTrustStore에 CA를 추가
                chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
                chain.ChainPolicy.VerificationFlags = X509VerificationFlags.NoFlag;
                chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
                chain.ChainPolicy.CustomTrustStore.Add(caCert);

                return chain.Build(cert); // chain.Build(cert) 결과를 반환
            }
            catch
            {
                return false; // 예외가 나면 false
            }
        }

        // 정적 메서드 ValidateWithThumbprint 선언
        // 설정된 지문과 서버 인증서 지문이 일치하는지로 신뢰 여부를 판단
        private static bool ValidateWithThumbprint(
            PublisherConnectionSettings settings, // 퍼블리셔 연결 설정
            X509Certificate2 cert // 서버 인증서
        )
        {
            // 설정된 지문을 NormalizeThumbprint로 정규화
            var expected = NormalizeThumbprint(settings.PinnedThumbprint);
            if (string.IsNullOrWhiteSpace(expected))
                return false;

            // 서버 인증서 Thumbprint도 정규화
            var actual = NormalizeThumbprint(cert.Thumbprint);
            // 대소문자 무시 비교로 동일하면 true를 반환
            return string.Equals(actual, expected, StringComparison.OrdinalIgnoreCase);
        }

        // 정적 메서드 NormalizeThumbprint 선언
        // 인증서 지문 문자열에서 콜론과 공백을 제거하고 비교하기 쉬운 형태로 정규화
        private static string? NormalizeThumbprint(string? thumbprint)
        {
            // 입력이 비어 있으면 null 반환
            if (string.IsNullOrWhiteSpace(thumbprint))
                return null;

            // ":" 와 " " 를 제거하고 Trim한 문자열을 반환
            return thumbprint.Replace(":", string.Empty).Replace(" ", string.Empty).Trim();
        }

        // 비동기 메서드 DoConnectAsync 선언
        // MQTT 클라이언트를 옵션으로 연결하고 결과 코드에 따라 성공 또는 오류 상태를 반영
        private async Task DoConnectAsync(
            IMqttClient client, // MQTT 클라이언트
            MqttClientOptions options, // 접속 옵션
            CancellationToken ct // 작업 취소 토큰
        )
        {
            try
            {
                // client.ConnectAsync(options, ct)로 연결을 시도
                var result = await client.ConnectAsync(options, ct);

                // ResultCode가 Success가 아니면
                if (result.ResultCode != MqttClientConnectResultCode.Success)
                {
                    // reason을 ResultCode 또는 ReasonString으로 구성
                    var reason = string.IsNullOrWhiteSpace(result.ReasonString)
                        ? result.ResultCode.ToString()
                        : result.ReasonString;

                    // 상태를 Error로 설정하고 로그를 남긴 뒤 InvalidOperationException를 던짐
                    SetState(ConnectionState.Error, reason);
                    WriteLog($"Connect rejected: {reason}");
                    throw new InvalidOperationException($"Connect rejected: {reason}");
                }
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested)
            {
                // 취소 예외는 Disconnected로 상태를 맞추고 Canceled로 상세 내용 입력
                SetState(ConnectionState.Disconnected, "Canceled");
                WriteLog("Connect canceled.");
                throw;
            }
            catch (Exception ex)
            {
                // 일반 예외는 Error 상태로 바꾸고 예외 타입과 메시지를 로그로 남김
                SetState(ConnectionState.Error, ex.Message);
                WriteLog($"Connect failed: {ex.GetType().Name}: {ex.Message}");
                throw;
            }
        }

        // 인스턴스 메서드 RegisterClientEventHandlers 선언
        // 클라이언트 이벤트 핸들러를 한 번 만들어 재사용하고, 실제 클라이언트 이벤트에 구독
        private void RegisterClientEventHandlers(IMqttClient client)
        {
            // _onConnected, _onDisconnected, _onMessageReceived가 null이면 각각 메서드를 할당
            _onConnected ??= OnConnectedAsync;
            _onDisconnected ??= OnDisconnectedAsync;
            _onMessageReceived ??= OnMessageReceivedAsync;

            // client 이벤트에 +=로 핸들러를 등록
            client.ConnectedAsync += _onConnected;
            client.DisconnectedAsync += _onDisconnected;
            client.ApplicationMessageReceivedAsync += _onMessageReceived;
        }

        // 인스턴스 메서드 UnregisterClientEventHandlers 선언
        // 등록했던 클라이언트 이벤트 핸들러를 해제
        // * Dispose나 Reset 전에 호출되어야 중복 구독과 누수를 막음
        private void UnregisterClientEventHandlers(IMqttClient client)
        {
            // 각 핸들러가 null이 아닐 때만 -=로 해제
            if (_onConnected != null)
                client.ConnectedAsync -= _onConnected;
            if (_onDisconnected != null)
                client.DisconnectedAsync -= _onDisconnected;
            if (_onMessageReceived != null)
                client.ApplicationMessageReceivedAsync -= _onMessageReceived;
        }

        // 비동기 메서드 OnConnectedAsync 선언
        // 연결 이벤트가 발생했을 때 로그만 남기는 핸들러
        private Task OnConnectedAsync(MqttClientConnectedEventArgs e)
        {
            // Connected event received 로그를 남기고 즉시 완료된 Task를 반환
            WriteLog("Connected event received.");
            return Task.CompletedTask;
        }

        // 비동기 메서드 OnDisconnectedAsync 선언
        // 연결 해제 이벤트가 발생했을 때 로그를 남기고 상태를 Disconnected로 갱신
        private Task OnDisconnectedAsync(MqttClientDisconnectedEventArgs e)
        {
            // e.Exception이 있으면 그 메시지를 사용하고 없으면 e.Reason을 문자열로 사용
            var msg = e.Exception != null ? e.Exception.Message : e.Reason.ToString();
            // 로그를 남김
            WriteLog($"Disconnected event received: {msg}");

            // 현재 연결 상태가 아니라면 Disconnected 상태로 갱신
            if (!IsConnected)
                SetState(ConnectionState.Disconnected, msg);

            // 완료된 Task를 반환
            return Task.CompletedTask;
        }

        // 비동기 메서드 OnMessageReceivedAsync 선언
        // 구독 메시지를 수신했을 때 PublisherMessage로 변환해 외부로 전달하고 로그를 남김
        private Task OnMessageReceivedAsync(MqttApplicationMessageReceivedEventArgs e)
        {
            // 토픽과 payload를 꺼냄
            var topic = e.ApplicationMessage.Topic;
            var payloadText = PayloadUtf8.Decode(e.ApplicationMessage.Payload);

            // MessageReceived 이벤트가 구독되어 있으면 PublisherMessage를 전달
            MessageReceived?.Invoke(
                new PublisherMessage
                {
                    Topic = topic, // 메시지 토픽
                    PayloadText = payloadText, // 메시지 페이로드
                    ReceivedAtUtc = DateTime.UtcNow, // 수신 시각 (UTC)
                }
            );

            // 수신 로그를 남기고 완료된 Task를 반환
            WriteLog($"Received: Topic={topic}");
            return Task.CompletedTask;
        }

        // 인스턴스 메서드 EnsureConnected 선언
        // 클라이언트가 없거나 연결되지 않았으면 예외를 던져 호출을 막음
        private void EnsureConnected()
        {
            // _client == null 또는 _client.IsConnected == false면 InvalidOperationException을 던진다
            if (_client == null || !_client.IsConnected)
                throw new InvalidOperationException("Client is not connected.");
        }

        // 인스턴스 메서드 WriteLog 선언
        // WriteLog는 로그 이벤트를 통해 메시지를 외부로 전달
        private void WriteLog(string message) => Log?.Invoke(message); // 구독자가 있을 때만 호출

        // 인스턴스 메서드 SetState 선언
        // SetState는 연결 상태 변경 이벤트를 통해 상태와 상세 정보를 외부로 전달
        private void SetState(ConnectionState state, string? detail) =>
            ConnectionStateChanged?.Invoke(state, detail); // 구독자가 있을 때만 호출
    }
}
