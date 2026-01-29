using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Text;

namespace MQTT_TLS_Bridge.Control
{
    // 상속이 불가능하도록 sealed 키워드 사용
    // TCP로 들어오는 INI 형태 요청 패킷을 읽어서 IniRequest로 파싱하고,
    // 외부에서 주입된 핸들러 Func<IniRequest, Task<IniResponse>>로 처리한 뒤
    // IniResponse를 INI 텍스트로 직렬화해 응답
    public sealed class IniControlServer
    {
        private const string ErrBadRequest = "BadRequest";

        // 읽기 전용 멤버 변수
        // 서버가 바인딩할 주소와 포트
        private readonly IPAddress _bindAddress;
        private readonly int _port;

        // 요청을 처리해 응답을 만드는 비동기 핸들러
        private readonly Func<IniRequest, Task<IniResponse>> _handler;

        // 리스너와 종료 신호, accept 루프 태스크를 관리하는 런타임 상태
        private TcpListener? _listener;
        private CancellationTokenSource? _internalCts;
        private Task? _acceptLoopTask;

        // 클라이언트 연결, 해제 이벤트
        public event Action<string>? ClientConnected;
        public event Action<string>? ClientDisconnected;

        // remote, id, cmd 전달
        public event Action<string, string, string>? PacketReceived;

        // remote, id, ok 전달
        public event Action<string, string, bool>? PacketSent;

        // remote, raw 텍스트 전달 및 수신
        public event Action<string, string>? RawReceived;
        public event Action<string, string>? RawSent;

        // 생성자
        public IniControlServer(
            IPAddress bindAddress, // 바인딩할 IP 주소
            int port, // 바인딩할 포트
            Func<IniRequest, Task<IniResponse>> handler // 요청 처리 핸들러
        )
        {
            _bindAddress = bindAddress;
            _port = port;
            _handler = handler ?? throw new ArgumentNullException(nameof(handler)); // 핸들러가 null인 경우 예외 발생
        }

        // 서버 시작 메서드
        // TcpListener를 생성해 Listen을 시작하고, accept 루프를 백그라운드 태스크로 실행
        public void Start(CancellationToken externalToken)
        {
            // _listener != null이면 이미 시작된 것으로 보고 아무것도 하지 않음
            if (_listener != null)
                return;

            // 애플리케이션 종료 시 멈출 수 있도록 외부 토큰과 연결된 내부 토큰 생성
            _internalCts = CancellationTokenSource.CreateLinkedTokenSource(externalToken);

            // 리스너를 만들고 Start()로 수신을 시작
            _listener = new TcpListener(_bindAddress, _port);
            _listener.Start();

            // accept 루프를 실행
            // 별도 태스크에서 실행하여 비동기적으로 클라이언트 연결을 수락
            _acceptLoopTask = Task.Run(
                () => AcceptLoopAsync(_internalCts.Token),
                _internalCts.Token
            );
        }

        // 서버 중지 메서드
        // 서버 종료 요청을 걸고 리스너를 중지한 뒤 accept 루프가 종료될 때까지 기다린 다음 리소스를 정리
        public async Task StopAsync()
        {
            // _listener == null이면 이미 멈춘 상태로 보고 종료
            if (_listener == null)
                return;

            try
            {
                // 토큰이 null이 아니면 종료 신호를 보내고 대기
                if (_internalCts != null)
                    await _internalCts.CancelAsync().ConfigureAwait(false);
            }
            catch
            {
                // 중지 경로에서의 예외는 종료/정리 흐름을 막지 않음
            }

            try
            {
                // 수신 중지
                _listener.Stop();
            }
            catch
            {
                // 이미 Stop 되었거나 Dispose 상태일 수 있으므로 무시
            }

            if (_acceptLoopTask != null)
            {
                try
                {
                    // _acceptLoopTask가 null이 아닐경우 종료될 때까지 대기
                    await _acceptLoopTask.ConfigureAwait(false);
                }
                catch
                {
                    // 종료 중 accept loop 예외는 무시
                }
            }

            try
            {
                // 토큰 해제
                _internalCts?.Dispose();
            }
            catch
            {
                // 정리 중 예외 무시
            }

            // 내부 필드 초기화
            _internalCts = null;
            _listener = null;
            _acceptLoopTask = null;
        }

        // 클라이언트 접속을 계속 받아들이는 루프
        private async Task AcceptLoopAsync(CancellationToken token)
        {
            // _listener가 null이면 실행할 수 없으므로 종료
            if (_listener == null)
                return;

            // 토큰이 취소될 때까지 AcceptTcpClientAsync(token)로 접속 대기
            while (!token.IsCancellationRequested)
            {
                TcpClient? client = null;

                try
                {
                    // ConfigureAwait(false): await 이후에 원래 스레드(컨텍스트)로 돌아오지 말라는 옵션
                    // await: 비동기 작업이 끝날 때까지 기다리고 결과를 받는 기능
                    // 서버 백그라운드 루프고 UI를 직접 만지지 않음 따라서 굳이 UI 컨텍스트로 복귀할 이유가 없음
                    client = await _listener.AcceptTcpClientAsync(token).ConfigureAwait(false);
                }
                catch (OperationCanceledException)
                {
                    // 취소 예외면 종료
                    client?.Dispose();
                    break;
                }
                catch
                {
                    // 그 외 예외는 토큰 상태를 보고 계속 또는 종료를 결정
                    client?.Dispose();
                    if (token.IsCancellationRequested)
                        break;

                    continue;
                }

                // 정상 접속이면 Task.Run(() => HandleClientAsync(client, token), token)으로 클라이언트를 처리
                _ = Task.Run(() => HandleClientAsync(client, token), token);
            }
        }

        // 단일 클라이언트 연결을 담당
        // 패킷 단위로 요청을 읽고 파싱하고 처리해 응답을 전송
        private async Task HandleClientAsync(TcpClient client, CancellationToken token)
        {
            var remote = SafeRemote(client); // SafeRemote로 클라이언트 원격 주소 문자열을 취득
            // ClientConnected 이벤트를 안전 호출해서 UI나 로그에서 접속을 알 수 있게 함
            // UI로 이벤트를 보낼 때 데드락 방지를 위해 SafeInvoke 사용
            SafeInvoke(ClientConnected, remote);

            try
            {
                // using: IDisposable 구현 객체의 Dispose 메서드를 자동으로 호출해 자원 해제를 보장
                //        개체의 사용이 끝나면 자동으로 Dispose를 호출
                using (client) // 함수가 끝나면 TcpClient를 Dispose하여 소켓을 닫는다
                using (var stream = client.GetStream()) // 네트워크 스트림을 가져온다
                using (
                    // StreamReader: 스트림에서 텍스트를 읽기 위한 헬퍼 클래스
                    var reader = new StreamReader(
                        stream, // 네트워크 스트림
                        Encoding.UTF8, // UTF-8 인코딩
                        detectEncodingFromByteOrderMarks: false, // BOM 감지 안함
                        bufferSize: 4096, // 버퍼 크기
                        leaveOpen: true // 스트림 닫지 않음
                    )
                )
                using (
                    // StreamWriter: 스트림에 텍스트를 쓰기 위한 헬퍼 클래스
                    var writer = new StreamWriter(
                        stream, // 네트워크 스트림
                        new UTF8Encoding(false), // UTF-8 인코딩 (BOM 없음)
                        bufferSize: 4096, // 버퍼 크기
                        leaveOpen: true // 스트림 닫지 않음
                    )
                    {
                        // 쓰기 후 자동 플러시(버퍼 비우기)
                        AutoFlush = true,
                    }
                )
                {
                    // 서버 종료 토큰이 취소되거나 클라이언트가 끊길 때까지 반복
                    while (!token.IsCancellationRequested)
                    {
                        // 빈 줄을 만날 때까지 라인들을 모아 하나의 패킷으로 만듦
                        var lines = await ReadPacketLinesAsync(reader, token).ConfigureAwait(false);
                        // 반환이 null이면 연결이 끊겼거나 읽기 실패이므로 함수 종료
                        if (lines == null)
                            return;

                        // 라인이 0개면 빈 패킷이므로 무시하고 다음 루프로 이동
                        if (lines.Count == 0)
                            continue;

                        // raw request 기록 (ReadLine이 CRLF를 제거하므로 여기서 복원)
                        RaiseRawReceived(remote, SerializeRawLines(lines));

                        // lines를 IniRequest로 파싱하고 외부에서 주입된 _handler로 처리한 뒤 IniResponse를 만듬
                        var resp = await ProcessOnePacketAsync(lines, remote).ConfigureAwait(false);

                        // IniResponse.Values를 INI 텍스트로 직렬화
                        var packetText = IniPacketFormatter.SerializeResponse(resp);

                        // raw response 기록
                        RaiseRawSent(remote, packetText);
                        // writer로 응답을 전송
                        await writer.WriteAsync(packetText).ConfigureAwait(false);
                        // 전송 후 PacketSent 이벤트로 id와 성공 여부를 전달
                        // UI로 이벤트를 보낼 때 데드락 방지를 위해 SafeInvoke 사용
                        SafeInvoke(PacketSent, remote, resp.Id, resp.IsOk);
                    }
                }
            }
            finally
            {
                // ClientDisconnected 이벤트를 안전 호출해서 UI나 로그에서 접속 해제를 알 수 있게 함
                // UI로 이벤트를 보낼 때 데드락 방지를 위해 SafeInvoke 사용
                SafeInvoke(ClientDisconnected, remote);
            }
        }

        // StreamReader에서 빈 줄을 만날 때까지 라인들을 읽어 리스트로 반환
        private static async Task<List<string>?> ReadPacketLinesAsync(
            StreamReader reader, // 읽기 대상 스트림 리더
            CancellationToken token // 취소 토큰
        )
        {
            var lines = new List<string>(); // 읽은 라인들을 저장할 리스트

            while (true)
            {
                string? line;
                try
                {
                    // 비동기적으로 한 라인 읽기
                    line = await reader.ReadLineAsync(token).ConfigureAwait(false);
                }
                catch
                {
                    // 읽기 실패 시 null 반환
                    return null;
                }

                // 스트림이 닫히거나 연결이 끊기면 null 반환
                if (line == null)
                    return null;

                // 빈 줄은 패킷 종료
                if (line.Length == 0)
                    break;

                // 읽은 라인을 리스트에 추가
                lines.Add(line);
            }

            // 읽은 라인들 반환
            return lines;
        }

        // 클라이언트로부터 받은 한 패킷(lines)을 IniRequest로 파싱하고
        // 수신 이벤트를 알린 뒤 외부 핸들러 _handler로 처리해서 IniResponse를 만듬
        private async Task<IniResponse> ProcessOnePacketAsync(List<string> lines, string remote)
        {
            // lines를 INI key value로 해석해서 IniRequest를 만들려고 시도
            // 실패하면 새 id를 생성, ErrBadRequest 에러 코드와 파싱 오류 메시지를 담은 Failure 응답을 반환
            if (!IniPacketFormatter.TryParseRequest(lines, out var req, out var parseError))
                return IniResponse.Failure(Guid.NewGuid().ToString("N"), ErrBadRequest, parseError);

            // TryParseRequest가 true를 반환했는데도 req가 null인 이상 상황을 방어
            if (req == null)
                return IniResponse.Failure(
                    Guid.NewGuid().ToString("N"),
                    ErrBadRequest,
                    "request is null."
                );

            // 패킷 수신 이벤트 발생
            // SafeInvoke라서 이벤트 구독자가 예외를 던져도 서버 처리는 계속
            SafeInvoke(PacketReceived, remote, req.Id, req.Command);

            try
            {
                // 이 서버는 실제 비즈니스 로직을 직접 처리하지 않고_handler에 위임
                // IniRequest를 받아 IniResponse를 비동기적으로 반환
                return await _handler(req).ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                // 핸들러 내부에서 예외가 나면 서버가 죽지 않게 Catch에서 응답으로 변환
                return IniResponse.Failure(req.Id, ex.GetType().Name, ex.Message);
            }
        }

        // TcpClient에서 원격 주소 문자열을 예외 없이 안전하게 가져오기 위한 헬퍼 함수
        private static string SafeRemote(TcpClient client)
        {
            try
            {
                // client.Client는 내부 Socket 객체
                // RemoteEndPoint는 상대방 IP와 포트 정보
                // RemoteEndPoint가 null일 수 있으니 null이면 ToString을 호출하지 않음
                // 최종 결과가 null이면 "unknown"으로 대체
                return client.Client.RemoteEndPoint?.ToString() ?? "unknown";
            }
            catch
            {
                // 소켓이 이미 닫혔거나, 엔드포인트 접근이 실패하는 경우 예외 발생 가능성 있음
                // "unknown"을 반환
                return "unknown";
            }
        }

        // raw request를 외부로 알리기 위해 RawReceived 이벤트를 호출
        private void RaiseRawReceived(string remote, string raw)
        {
            // 이벤트 구독자 존재 여부 확인
            // 이벤트를 로컬 변수 h에 복사하는 이유는 호출 시점에 이벤트가 변경될 수 있는 상황을 줄이기 위한 패턴
            var h = RawReceived;
            if (h == null)
                return;

            try
            {
                // 원격 주소(remote)와 원문 텍스트(raw)를 전달
                h(remote, raw);
            }
            catch
            {
                // Raw 로깅은 진단용 보조 기능이므로 실패해도 서버 처리 흐름을 중단하지 않음
            }
        }

        // 전송할 raw response를 외부로 알리기 위해 RawSent 이벤트를 호출
        private void RaiseRawSent(string remote, string raw)
        {
            // 이벤트 구독자 존재 여부 확인
            // 이벤트를 로컬 변수 h에 복사하는 이유는 호출 시점에 이벤트가 변경될 수 있는 상황을 줄이기 위한 패턴
            var h = RawSent;
            if (h == null)
                return;

            try
            {
                // 원격 주소(remote)와 전송할 원문 텍스트(raw)를 전달
                h(remote, raw);
            }
            catch
            {
                // Raw 로깅은 진단용 보조 기능이므로 실패해도 서버 처리 흐름을 중단하지 않음
            }
        }

        // ReadLine으로 읽어온 라인 리스트를 원래 네트워크에서 받은 패킷 형태로 다시 합쳐서 문자열로 치환
        private static string SerializeRawLines(List<string> lines)
        {
            // 요청은 "라인들 + CRLF + CRLF" 형태로 네트워크 패킷을 복원
            // (ReadLine은 CRLF 제거하므로 여기서 재부착)
            // 여러 문자열을 반복해서 붙이기 때문에 성능상 StringBuilder를 사용
            var sb = new StringBuilder();

            // ReadLine은 줄 끝의 \r\n을 제거하고 문자열만 반환
            foreach (var line in lines)
            {
                sb.Append(line ?? string.Empty);
                sb.Append("\r\n");
            }

            // 빈 줄은 패킷 끝을 의미
            sb.Append("\r\n");
            return sb.ToString();
        }

        // Action<string> 타입 이벤트를 안전하게 호출하기 위한 헬퍼
        private static void SafeInvoke(Action<string>? ev, string a1)
        {
            // 이벤트가 null이면 구독자가 없다는 뜻이므로 호출하지 않고 종료
            if (ev == null)
                return;

            try
            {
                ev(a1);
            }
            catch
            {
                // 이벤트 핸들러 예외는 외부 소비자 책임이며 서버 루프 안정성을 위해 무시
            }
        }

        // Action<string, string, string> 타입 이벤트를 안전하게 호출하기 위한 헬퍼
        private static void SafeInvoke(
            Action<string, string, string>? ev,
            string a1,
            string a2,
            string a3
        )
        {
            // 이벤트가 null이면 구독자가 없다는 뜻이므로 호출하지 않고 종료
            if (ev == null)
                return;

            try
            {
                ev(a1, a2, a3);
            }
            catch
            {
                // 이벤트 핸들러 예외는 외부 소비자 책임이며 서버 루프 안정성을 위해 무시
            }
        }

        // Action<string, string, bool> 타입 이벤트를 안전하게 호출하기 위한 헬퍼
        private static void SafeInvoke(
            Action<string, string, bool>? ev,
            string a1,
            string a2,
            bool a3
        )
        {
            // 이벤트가 null이면 구독자가 없다는 뜻이므로 호출하지 않고 종료
            if (ev == null)
                return;

            try
            {
                ev(a1, a2, a3);
            }
            catch
            {
                // 이벤트 핸들러 예외는 외부 소비자 책임이며 서버 루프 안정성을 위해 무시
            }
        }
    }
}
