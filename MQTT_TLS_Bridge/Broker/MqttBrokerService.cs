using System.Net;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using MQTT_TLS_Bridge.Utils;
using MQTTnet.Server;

namespace MQTT_TLS_Bridge.Broker
{
    // [IAsyncDisposable]
    // 리소스 해제 시 비동기 처리를 지원하는 인터페이스
    // == IDisposable ==
    // 메서드: void Dispose()
    // 파일 핸들, 메모리, 타이머 같은 동기적으로 바로 정리 가능한 것에 사용
    // == IAsyncDisposable ==
    // 메서드: ValueTask DisposeAsync()
    // 네트워크 연결, 데이터베이스 연결 같은 비동기적으로 정리해야 하는 것에 사용

    // 인스턴스화 할수 있으나, 상속은 불가한 클래스
    // IAsyncDisposable를 구현(implement)하여 비동기적으로 리소스를 해제하는 기능을 제공
    public sealed class MqttBrokerService : IAsyncDisposable
    {
        // nullable MqttServer 변수 선언
        private MqttServer? _server;

        // 로드된 인증서를 보관하는 nullable X509Certificate2 변수 선언
        private X509Certificate2? _certificate;

        // 서버의 실행 상태를 나타내는 읽기 전용 속성
        // 멤버에서 =>와 같이 람다가 나오면 보통 getter(읽기 전용 속성)임
        // 만약 setter(쓰기 전용 속성)도 있으면 {get; private set;} 형태로 작성됨
        public bool IsRunning => _server?.IsStarted == true;

        // 로그 이벤트와 메시지 수신 이벤트 선언
        // Action<T>는 입력만 받고 반환값이 없음
        // ?는 null 허용 참조 형식 표시
        // 예) Action<String> = String 입력을 받아 void로 끝나는 함수
        // event를 안썼을 경우에는 ~.Log = null; 같은 식으로 외부에서 덮어쓰거나
        // ~.Log("Hack"); 같은 식으로 호출도 가능해짐
        public event Action<string>? Log;
        public event Action<BrokerMessage>? MessageReceived;

        // async Task: 비동기 메서드(완료될 때 까지 await으로 대기 가능)
        // StartAsync 메서드: MQTT 브로커 서버를 시작하는 비동기 메서드
        public async Task StartAsync(
            string pfxPath, // 서버 TLS 인증서 파일 경로
            string pfxPassword, // pfx 파일 비밀번호
            int port, // MQTT/TLS 포트
            SslProtocols sslProtocols, // TLS 프로토콜 버전 (TLS1.2, TLS1.3 등)
            CancellationToken cancellationToken // 취소 요청이 들어오면 중단하기 위한 토큰
        )
        {
            // 취소 요청이 있으면 OperationCanceledException 예외 발생
            // 시작 버튼 누르고 바로 취소 누르는 경우를 대비
            cancellationToken.ThrowIfCancellationRequested();

            // 이미 실행중인 경우 로그 출력 후 종료
            if (IsRunning)
            {
                WriteLog("Broker is already running.");
                return;
            }

            // 이전에 실행된 서버가 있으면 자원 해제
            if (_server != null)
                DisposeServer();

            // pfx 경로 유효성 검사
            // 경로가 null/빈문자/공백이면 에러
            if (string.IsNullOrWhiteSpace(pfxPath))
                throw new InvalidOperationException("PFX path is empty.");

            // PFX 파일을 열어서 X509Certificate2 같은 인증서 객체로 로드하는 유틸 호출
            var cert = CertUtil.LoadPkcs12FromFile(pfxPath, pfxPassword);

            // 서버 TLS는 인증서 + 개인키가 필요
            // 개인키가 없으면 서버가 TLS 핸드셰이크를 못 함
            // 없을 경우 cert Dispose() 후 예외 발생
            if (!cert.HasPrivateKey)
            {
                cert.Dispose();
                throw new CryptographicException("PFX does not contain a private key.");
            }

            // 개인키 접근 가능 여부 확인(RSA/ECDSA)
            // HasPrivateKey == true여도, 실제로 키를 꺼내려 하면 null이 나오는 경우가 있음
            // 예: 키 접근 권한 문제, 키 저장소 문제, CSP/KSP 문제 등
            // 접근 불가할 경우도 동일하게 cert Dispose() 후 예외 발생
            var rsa = cert.GetRSAPrivateKey();
            var ecdsa = cert.GetECDsaPrivateKey();
            if (rsa == null && ecdsa == null)
            {
                cert.Dispose();
                throw new CryptographicException(
                    "Private key is not accessible (RSA/ECDSA key is null)."
                );
            }

            // MQTTnet에서 서버/옵션을 생성해주는 팩토리
            // 이후 옵션 빌더를 만들고 서버 인스턴스를 생성하는 데 사용
            var serverFactory = new MqttServerFactory();

            // 서버 옵션 빌더를 사용하여 TLS 설정 포함한 서버 옵션 생성
            // 아래와 같은 패턴을 빌더(Builder) 패턴 또는 플루언트 빌더(Fluent Builder)라고 함
            // 메서드 체이닝: 내부 상태를 변경하고 자기 자신을 반환해서 다음 메서드를 .연결해서 계속 호출할 수 있게 함
            var options = serverFactory
                .CreateServerOptionsBuilder() // 서버 옵션 빌더 생성
                .WithoutDefaultEndpoint() // 기본 비암호화 엔드포인트 비활성화. 1883 같은 unencrypted 포트를 기본으로 열지 않겠다는 의미 (TLS만)
                .WithEncryptedEndpoint() // 암호화된 엔드포인트 활성화
                .WithEncryptedEndpointBoundIPAddress(IPAddress.Any) // 바인딩 주소를 0.0.0.0로 잡는 것과 동일
                .WithEncryptedEndpointPort(port) // 포트 설정
                .WithEncryptionCertificate(cert) // TLS 인증서 설정
                .WithEncryptionSslProtocol(sslProtocols) // TLS 프로토콜 버전 설정
                .Build(); // 최종적으로 MqttServerOptions 객체 생성

            // _server: 실제 MQTT 브로커 서버 인스턴스
            _server = serverFactory.CreateMqttServer(options);
            // _certificate: 나중에 종료할 때 Dispose하려고 필드로 들고 있음
            _certificate = cert;
            // 서버 이벤트 핸들러(연결/해제/메시지 수신 등) 등록
            RegisterServerEventHandlers(_server);

            try
            {
                // 다시 한 번 취소 요청 확인
                cancellationToken.ThrowIfCancellationRequested();
                // 서버 시작(비동기)
                await _server.StartAsync();
            }
            catch
            {
                // 서버 시작이 실패하면 서버 인스턴스 및 인증서 자원 해제
                DisposeServer();
                throw;
            }

            // 모든 과정이 성공하면 마지막에 로그 남김
            // Action<String> Log에 등록된 핸들러 호출
            // localhost라고 썼지만, 실제 바인딩은 IPAddress.Any라서 외부에서도 접속 가능할 수 있음
            WriteLog($"Broker started on mqtts://localhost:{port} ({sslProtocols}).");
        }

        // StopAsync 메서드: MQTT 브로커 서버를 중지하는 비동기 메서드
        public async Task StopAsync(CancellationToken cancellationToken)
        {
            // 취소 요청이 있으면 OperationCanceledException 예외 발생
            cancellationToken.ThrowIfCancellationRequested();

            // 서버 인스턴스가 없는 경우 로그 출력 후 종료
            if (_server == null)
            {
                WriteLog("Broker is not initialized.");
                return;
            }

            // 서버 인스턴스는 있으나, 실행 중이 아닌 경우에도 로그 출력 후 자원 해제
            if (!_server.IsStarted)
            {
                WriteLog("Broker is not running.");
                DisposeServer();
                return;
            }

            // 서버 중지(비동기)
            await _server.StopAsync();
            // 중지 완료 후 로그 출력
            // Action<String> Log에 등록된 핸들러 호출
            WriteLog("Broker stopped.");
            // 자원 해제
            DisposeServer();
        }

        // 해당 클래스의 리소스를 비동기 방식으로 정리하는 함수
        public async ValueTask DisposeAsync()
        {
            // 서버 인스턴스가 존재하는지 확인
            if (_server != null)
            {
                try
                {
                    // 서버가 실행 중인 경우에만 중지 시도
                    if (_server.IsStarted)
                        await _server.StopAsync();
                }
                finally
                {
                    // 서버 인스턴스 및 인증서 자원 해제
                    DisposeServer();
                }
            }
        }

        // 서버와 인증서 리소스를 동기 방식으로 최종 해제하는 함수.
        private void DisposeServer()
        {
            // 서버 인스턴스가 존재하는지 확인
            if (_server != null)
            {
                try
                {
                    // 서버 인스턴스가 존재하면 Dispose() 호출하여 자원 해제
                    _server.Dispose();
                }
                finally
                {
                    // 없을 경우 null로 설정
                    _server = null;
                }
            }

            // 인증서 인스턴스가 존재하는지 확인
            // 인증서는 내부적으로 네이티브 핸들을 들고 있을 수 있어서 Dispose가 필요
            // Dispose() 후 _certificate = null로 참조 제거
            _certificate?.Dispose();
            _certificate = null;
        }

        // MQTT 서버에서 발생하는 이벤트(클라이언트 연결, 연결 해제, Publish 수신)를 훅으로 받아서
        // 로그 출력 및 메시지 수신 이벤트를 발생시키는 함수
        private void RegisterServerEventHandlers(MqttServer server)
        {
            // 서버에 어떤 클라이언트가 붙었을 때
            server.ClientConnectedAsync += e =>
            {
                // 클라이언트 ID를 로그로 출력
                WriteLog($"Client connected: {e.ClientId}");
                // ClientConnectedAsync가 Async로 되어 있어서 Task 반환이 필수
                // 실제로 비동기 작업이 없어 Task.CompletedTask 반환
                return Task.CompletedTask;
            };

            // 서버에서 어떤 클라이언트가 끊겼을 때
            server.ClientDisconnectedAsync += e =>
            {
                // 클라이언트 ID와 끊긴 유형(예: 정상 종료, 네트워크 오류 등)을 로그로 출력
                WriteLog($"Client disconnected: {e.ClientId}, Type={e.DisconnectType}");
                // ClientDisconnectedAsync가 Async로 되어 있어서 Task 반환이 필수
                // 실제로 비동기 작업이 없어 Task.CompletedTask 반환
                return Task.CompletedTask;
            };

            // Intercept 이벤트 등록
            server.InterceptingPublishAsync += e =>
            {
                var topic = e.ApplicationMessage.Topic; // 토픽 추출
                var payloadText = PayloadUtf8.Decode(e.ApplicationMessage.Payload); // 페이로드를 UTF-8 문자열로 디코딩

                // Invoke의 동작: null이 아니면(등록된 델리게이트 또는 이벤트 구독자가 있으면) BrokerMessage 객체 전달
                MessageReceived?.Invoke(
                    new BrokerMessage
                    {
                        Topic = topic,
                        PayloadText = payloadText,
                        ReceivedAtUtc = DateTime.UtcNow, // 수신 시각(UTC)
                    }
                );

                // 어떤 클라이언트가 어떤 토픽으로 publish 했는지 기록
                WriteLog($"Publish intercepted: ClientId={e.ClientId}, Topic={topic}");
                // InterceptingPublishAsync가 Async로 되어 있어서 Task 반환이 필수
                // 실제로 비동기 작업이 없어 Task.CompletedTask 반환
                return Task.CompletedTask;
            };
        }

        // 로그 메시지를 기록하는 내부 메서드
        // Log 이벤트에 구독자가 있으면 메시지를 전달
        private void WriteLog(string message) => Log?.Invoke(message);
    }
}
