using System.IO;
using System.Text;
using System.Threading.Channels;

namespace MQTT_TLS_Bridge.Logging
{
    public sealed class DailyFileLogger : IAsyncDisposable
    {
        private readonly string _logDir;
        private readonly Channel<string> _ch;
        private readonly CancellationTokenSource _cts = new();
        private readonly Task _worker;

        private DateOnly _currentDate;
        private StreamWriter? _writer;

        // 로거 내부 오류를 외부로 알리고 싶을 때 사용 (UI/파일/디버그 등)
        public event Action<Exception>? InternalError;

        public DailyFileLogger(string logDir)
        {
            _logDir = logDir ?? throw new ArgumentNullException(nameof(logDir));
            Directory.CreateDirectory(_logDir);

            // Single reader ensures log ordering; allow multiple writers from UI/worker threads.
            _ch = Channel.CreateUnbounded<string>(
                new UnboundedChannelOptions { SingleReader = true, SingleWriter = false }
            );

            _currentDate = DateOnly.FromDateTime(DateTime.Now);
            _worker = Task.Run(WorkerAsync);
        }

        public void Write(string category, string message)
        {
            // Best-effort enqueue; failures are handled in worker/Dispose paths.
            var ts = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss.fff");
            _ch.Writer.TryWrite($"{ts} [{category}] {message}");
        }

        public void WriteRaw(string category, string remote, string direction, string rawText)
        {
            var ts = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss.fff");
            _ch.Writer.TryWrite($"{ts} [{category}] {direction} remote={remote}");
            _ch.Writer.TryWrite(rawText ?? string.Empty);
            _ch.Writer.TryWrite(string.Empty);
        }

        public void WriteBytes(
            string category,
            string remote,
            string direction,
            string topic,
            byte[] payload
        )
        {
            payload ??= [];

            var ts = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss.fff");
            var hex = Convert.ToHexString(payload);
            var b64 = Convert.ToBase64String(payload);

            _ch.Writer.TryWrite(
                $"{ts} [{category}] {direction} remote={remote} topic={topic} bytes={payload.Length}"
            );
            _ch.Writer.TryWrite($"hex={hex}");
            _ch.Writer.TryWrite($"b64={b64}");
            _ch.Writer.TryWrite(string.Empty);
        }

        private async Task WorkerAsync()
        {
            try
            {
                // Drain channel until cancellation to preserve log ordering.
                while (await _ch.Reader.WaitToReadAsync(_cts.Token).ConfigureAwait(false))
                {
                    while (_ch.Reader.TryRead(out var line))
                    {
                        await RotateIfNeededAsync().ConfigureAwait(false);

                        if (_writer != null)
                            await _writer.WriteLineAsync(line).ConfigureAwait(false);
                    }

                    if (_writer != null)
                        await _writer.FlushAsync().ConfigureAwait(false);
                }
            }
            catch (OperationCanceledException)
            {
                // 종료 시나리오: DisposeAsync에서 CancelAsync를 호출하므로 정상 종료로 간주합니다.
            }
            catch (Exception ex)
            {
                // 로깅 실패로 프로그램 전체가 중단되면 안 되므로 내부 오류로만 통지합니다.
                RaiseInternalError(ex);
            }
            finally
            {
                // 종료 시 남은 버퍼를 최대한 플러시하고 리소스를 정리합니다.
                try
                {
                    if (_writer != null)
                    {
                        await _writer.FlushAsync().ConfigureAwait(false);
                        await _writer.DisposeAsync().ConfigureAwait(false);
                    }
                }
                catch (Exception ex)
                {
                    // 종료 단계에서의 파일 I/O 실패는 복구 불가하므로 무시하되, 필요하면 외부로 알립니다.
                    RaiseInternalError(ex);
                }
            }
        }

        private async Task RotateIfNeededAsync()
        {
            var today = DateOnly.FromDateTime(DateTime.Now);
            if (_writer != null && today == _currentDate)
                return;

            _currentDate = today;

            if (_writer != null)
            {
                try
                {
                    await _writer.DisposeAsync().ConfigureAwait(false);
                }
                catch (Exception ex)
                {
                    // 파일 핸들 정리가 실패해도 다음 파일 오픈을 시도해야 하므로 계속 진행합니다.
                    RaiseInternalError(ex);
                }

                _writer = null;
            }

            var path = Path.Combine(_logDir, $"{_currentDate:yyyyMMdd}.log");

            try
            {
                // Open log file in append mode with UTF-8 (no BOM) for easy parsing.
                _writer = new StreamWriter(
                    path,
                    append: true,
                    new UTF8Encoding(encoderShouldEmitUTF8Identifier: false)
                )
                {
                    AutoFlush = false,
                };
            }
            catch (Exception ex)
            {
                // 디스크/권한 문제 등으로 파일을 열 수 없는 경우: 로거는 동작 불가.
                // 대신 내부 오류 이벤트로 알리고, 이후 라인은 버려집니다.
                _writer = null;
                RaiseInternalError(ex);
            }
        }

        public async ValueTask DisposeAsync()
        {
            try
            {
                await _cts.CancelAsync().ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                // 이미 취소된 CTS 등 종료 상황에서 발생할 수 있어 무시합니다.
                RaiseInternalError(ex);
            }

            try
            {
                _ch.Writer.TryComplete();
            }
            catch (Exception ex)
            {
                // 종료 시 채널 완료 실패는 치명적이지 않으므로 무시합니다.
                RaiseInternalError(ex);
            }

            try
            {
                await _worker.ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                // 워커 예외는 내부에서 이미 처리/통지되었을 가능성이 높으나, 안전하게 한 번 더 통지합니다.
                RaiseInternalError(ex);
            }

            try
            {
                _cts.Dispose();
            }
            catch (Exception ex)
            {
                // Dispose 단계 예외는 무시합니다.
                RaiseInternalError(ex);
            }
        }

        private void RaiseInternalError(Exception ex)
        {
            try
            {
                InternalError?.Invoke(ex);
            }
            catch
            { /* 내부 오류 통지 실패는 무시 */
            }
        }
    }
}
