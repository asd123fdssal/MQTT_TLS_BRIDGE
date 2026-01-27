using System;
using System.Windows.Controls;

namespace MQTT_TLS_Bridge
{
    public partial class MainWindow
    {
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
            AppendLog("BROKER", BrokerLogTextBox, message, MaxLogLines, TrimLogLines);
        }

        private void AppendClientLog(string message)
        {
            AppendLog("CLIENT", ClientLogTextBox, message, MaxLogLines, TrimLogLines);
        }

        private void AppendServerLog(string message)
        {
            AppendLog(LogServerName, ServerLogTextBox, message, MaxServerLogLines, TrimServerLogLines);
        }

        private void AppendLog(
            string logName,
            TextBox textBox,
            string message,
            int maxLines,
            int trimLines
        )
        {
            Dispatcher.Invoke(() =>
            {
                AppendLogLine(
                    textBox,
                    $"[{DateTime.Now:HH:mm:ss}] {message}\r\n",
                    maxLines,
                    trimLines
                );
                _fileLog.Write(logName, message);
            });
        }
    }
}
