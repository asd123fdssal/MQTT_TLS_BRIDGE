using System.Windows.Controls;

namespace MQTT_TLS_Bridge
{
    // TextBox에 로그를 추가하고, 라인 수가 많아지면 앞부분을 잘라서 메모리 증가를 막음
    // MainWindow 클래스의 일부로 정의
    public partial class MainWindow
    {
        // TextBox에 텍스트를 추가하고 최대 라인 수를 넘으면 앞쪽 라인 일부를 삭제해서 로그 크기를 제한
        private static void AppendLogLine(TextBox textBox, string line, int maxLines, int trimLines)
        {
            // line을 그대로 TextBox 끝에 붙임
            textBox.AppendText(line);

            // 라인 수가 제한을 넘지 않으면 스크롤만 맨 아래로 내리고 종료
            if (textBox.LineCount <= maxLines)
            {
                textBox.ScrollToEnd();
                return;
            }

            // 최소 1줄은 잘라내도록 강제
            if (trimLines < 1)
                trimLines = 1;

            // 잘라낼 라인 수가 현재 라인 수 이상이면 부분 삭제가 의미 없으니 그냥 전체 삭제
            if (trimLines >= textBox.LineCount)
            {
                textBox.Clear();
                return;
            }

            // trimLines번째 라인이 시작되는 문자 인덱스를 구함
            // 0부터 그 지점까지 선택해서 SelectedText = ""로 삭제
            var charIndex = textBox.GetCharacterIndexFromLineIndex(trimLines);
            if (charIndex > 0)
            {
                textBox.Select(0, charIndex);
                textBox.SelectedText = string.Empty;
            }

            // 커서를 맨 끝으로 옮기고 스크롤도 맨 아래로 내림
            textBox.CaretIndex = textBox.Text.Length;
            textBox.ScrollToEnd();
        }

        // Broker 로그를 해당 TextBox에 붙이기 위한 편의 함수
        private void AppendBrokerLog(string message)
        {
            // UI에서 사용할 TextBox와 라인 제한 값을 고정해서 넘김
            AppendLog("BROKER", BrokerLogTextBox, message, MaxLogLines, TrimLogLines);
        }

        // Client 로그를 해당 TextBox에 붙이기 위한 편의 함수
        private void AppendClientLog(string message)
        {
            // UI에서 사용할 TextBox와 라인 제한 값을 고정해서 넘김
            AppendLog("CLIENT", ClientLogTextBox, message, MaxLogLines, TrimLogLines);
        }

        // Server 로그를 해당 TextBox에 붙이기 위한 편의 함수
        private void AppendServerLog(string message)
        {
            // UI에서 사용할 TextBox와 라인 제한 값을 고정해서 넘김
            AppendLog(
                LogServerName,
                ServerLogTextBox,
                message,
                MaxServerLogLines,
                TrimServerLogLines
            );
        }

        // UI 스레드에서 TextBox에 로그 라인을 추가
        private void AppendLog(
            string logName, // 로그 카테고리 이름 (파일 로거용)
            TextBox textBox, // 로그를 추가할 TextBox
            string message, // 추가할 로그 메시지
            int maxLines, // 최대 라인 수
            int trimLines // 잘라낼 라인 수
        )
        {
            Dispatcher.Invoke(() =>
            {
                // UI 로그 크기를 제한해서 메모리가 무한히 증가하는 것을 방지
                AppendLogLine(
                    textBox,
                    $"[{DateTime.Now:HH:mm:ss}] {message}\r\n",
                    maxLines,
                    trimLines
                );
                // 로그 라인을 일별 파일 로거에 저장
                _fileLog.Write(logName, message);
            });
        }
    }
}
