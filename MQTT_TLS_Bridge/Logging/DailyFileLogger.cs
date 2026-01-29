using System.IO;
using System.Text;
using System.Threading.Channels;

namespace MQTT_TLS_Bridge.Logging
{
    // 로그 문자열을 Channel에 넣고, 백그라운드 워커가 파일에 순서대로 기록하는 비동기 파일 로거
    // 종료 시 DisposeAsync로 워커를 정리한다
    public sealed class DailyFileLogger : IAsyncDisposable
    {
        private readonly string _logDir; // 로그 파일이 저장될 디렉터리
        private readonly Channel<string> _ch; // 로그 메시지 채널
        private readonly CancellationTokenSource _cts = new(); // 워커 취소용 CTS
        private readonly Task _worker; // 백그라운드 워커 태스크

        private DateOnly _currentDate; // 현재 열려있는 로그 파일의 날짜
        private StreamWriter? _writer; // 현재 열려있는 로그 파일의 스트림 라이터

        // 로거 내부 오류를 외부로 알리고 싶을 때 사용 (UI/파일/디버그 등)
        public event Action<Exception>? InternalError;

        // 로그 폴더를 만들고, 채널과 워커를 초기화
        public DailyFileLogger(string logDir)
        {
            // 폴더 경로 null이면 예외 폴더가 없으면 생성
            _logDir = logDir ?? throw new ArgumentNullException(nameof(logDir));
            Directory.CreateDirectory(_logDir);

            // 단일 리더로 로그 순서를 보장하고, 여러 스레드에서 쓰는 것은 허용
            // 제한 없는 채널 생성
            // SingleReader = true: 읽는 쪽은 워커 1개 → 순서 보장하기 쉬움
            // SingleWriter = false: 쓰는 쪽은 여러 스레드(UI/ 네트워크 / 워커) 가능
            _ch = Channel.CreateUnbounded<string>(
                new UnboundedChannelOptions { SingleReader = true, SingleWriter = false }
            );

            // 현재 날짜 저장
            _currentDate = DateOnly.FromDateTime(DateTime.Now);
            // 워커를 백그라운드로 시작
            _worker = Task.Run(WorkerAsync);
        }

        // 일반 로그 한 줄을 채널에 넣음 (즉시 파일에 쓰지 않음)
        public void Write(string category, string message)
        {
            // 가능하면 큐에 넣고, 실패는 워커나 종료 경로에서 처리함
            // 예외를 던지지 않음
            var ts = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss.fff");
            _ch.Writer.TryWrite($"{ts} [{category}] {message}");
        }

        // 원본(raw) 로그를 여러 줄로 기록하기 위해 채널에 여러 줄을 넣음
        public void WriteRaw(string category, string remote, string direction, string rawText)
        {
            var ts = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss.fff");
            _ch.Writer.TryWrite($"{ts} [{category}] {direction} remote={remote}");
            _ch.Writer.TryWrite(rawText ?? string.Empty);
            _ch.Writer.TryWrite(string.Empty);
        }

        // payload 바이트를 hex/base64로 변환해서 기록
        public void WriteBytes(
            string category, // 로그 카테고리
            string remote, // 원격지 식별자 (예: IP:포트)
            string direction, // 방향
            string topic, // MQTT 토픽
            byte[] payload // payload 바이트 배열
        )
        {
            // payload가 null이면 빈 배열로 처리
            payload ??= [];

            // hex와 base64 문자열 생성
            var ts = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss.fff");
            var hex = Convert.ToHexString(payload);
            var b64 = Convert.ToBase64String(payload);

            // 가능하면 큐에 입력
            _ch.Writer.TryWrite(
                $"{ts} [{category}] {direction} remote={remote} topic={topic} bytes={payload.Length}"
            );
            _ch.Writer.TryWrite($"hex={hex}");
            _ch.Writer.TryWrite($"b64={b64}");
            _ch.Writer.TryWrite(string.Empty);
        }

        // 채널에서 로그를 읽어 파일에 순서대로 기록하는 메인 워커 루프
        private async Task WorkerAsync()
        {
            try
            {
                // 취소될 때까지 채널을 비워서 로그 순서를 보존
                // 읽을 것이 생길 때까지 대기
                while (await _ch.Reader.WaitToReadAsync(_cts.Token).ConfigureAwait(false))
                {
                    // 읽기
                    while (_ch.Reader.TryRead(out var line))
                    {
                        // 날짜 변경 체크 후 로테이션
                        await RotateIfNeededAsync().ConfigureAwait(false);

                        // writer가 있으면 한 줄씩 기록
                        if (_writer != null)
                            await _writer.WriteLineAsync(line).ConfigureAwait(false);
                    }

                    // 배치 처리 후 Flush
                    if (_writer != null)
                        await _writer.FlushAsync().ConfigureAwait(false);
                }
            }
            catch (OperationCanceledException)
            {
                // 종료 시나리오: DisposeAsync에서 CancelAsync를 호출하므로 정상 종료로 간주함
            }
            catch (Exception ex)
            {
                // 로깅 실패로 프로그램 전체가 중단되면 안 되므로 내부 오류로만 통지
                RaiseInternalError(ex);
            }
            finally
            {
                // 종료 시 남은 버퍼를 최대한 플러시하고 리소스를 정리
                try
                {
                    if (_writer != null)
                    {
                        // 버퍼에 남은 것들을 flush 하고 닫음
                        await _writer.FlushAsync().ConfigureAwait(false);
                        await _writer.DisposeAsync().ConfigureAwait(false);
                    }
                }
                catch (Exception ex)
                {
                    // 종료 단계에서의 파일 I/O 실패는 복구 불가하므로 무시하되, 필요하면 외부로 알림
                    RaiseInternalError(ex);
                }
            }
        }

        // 날짜가 바뀌었거나 writer가 없으면 새 로그 파일에 기록
        private async Task RotateIfNeededAsync()
        {
            // writer가 있고 날짜가 그대로면 아무 것도 안 함
            var today = DateOnly.FromDateTime(DateTime.Now);
            if (_writer != null && today == _currentDate)
                return;

            // 현재 날짜 갱신
            _currentDate = today;

            if (_writer != null)
            {
                try
                {
                    // 기존 writer 정리(실패해도 다음으로 진행)
                    await _writer.DisposeAsync().ConfigureAwait(false);
                }
                catch (Exception ex)
                {
                    // 파일 핸들 정리가 실패해도 다음 파일 오픈을 시도해야 하므로 계속 진행합니다.
                    RaiseInternalError(ex);
                }

                _writer = null;
            }

            // 날짜 기반 파일명으로 새 파일 오픈
            var path = Path.Combine(_logDir, $"{_currentDate:yyyyMMdd}.log");

            try
            {
                _writer = new StreamWriter(
                    path, // 파일 경로
                    append: true, // 기존 파일에 추가
                    new UTF8Encoding(encoderShouldEmitUTF8Identifier: false) // UTF8 인코딩 (BOM 없음)
                )
                {
                    AutoFlush = false, // 수동 Flush (성능 향상 목적)
                };
            }
            catch (Exception ex)
            {
                // 디스크/권한 문제 등으로 파일을 열 수 없는 경우: 로거는 동작 불가.
                // 대신 내부 오류 이벤트로 알리고, 이후 라인은 버려짐
                _writer = null;
                RaiseInternalError(ex);
            }
        }

        // 워커를 정상 종료시키고 리소스를 정리
        public async ValueTask DisposeAsync()
        {
            try
            {
                // 워커 취소 요청
                await _cts.CancelAsync().ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                // 이미 취소된 CTS 등 종료 상황에서 발생할 수 있어 무시
                RaiseInternalError(ex);
            }

            try
            {
                // 더 이상 로그를 받지 않음
                _ch.Writer.TryComplete();
            }
            catch (Exception ex)
            {
                // 종료 시 채널 완료 실패는 치명적이지 않으므로 무시
                RaiseInternalError(ex);
            }

            try
            {
                // 워커가 종료될 때까지 대기
                await _worker.ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                // 워커 예외는 내부에서 이미 처리/통지되었을 가능성이 높으나, 안전하게 한 번 더 통지
                RaiseInternalError(ex);
            }

            try
            {
                // CTS 리소스 정리
                _cts.Dispose();
            }
            catch (Exception ex)
            {
                // Dispose 단계 예외는 무시합니다.
                RaiseInternalError(ex);
            }
        }

        // InternalError 이벤트를 안전하게 호출
        private void RaiseInternalError(Exception ex)
        {
            try
            {
                // 구독자가 있으면 호출
                // 구독자가 예외를 던져도 로거가 죽지 않게 catch로 감쌈
                InternalError?.Invoke(ex);
            }
            catch
            { /* 내부 오류 통지 실패는 무시 */
            }
        }
    }
}
