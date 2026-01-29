using System.Collections.Concurrent;
using System.Collections.ObjectModel;
using System.Windows.Controls;
using MQTT_TLS_Bridge.Broker;
using MQTT_TLS_Bridge.Publisher;

namespace MQTT_TLS_Bridge
{
    // 브로커/클라이언트에서 받은 메시지의 토픽 목록을 UI에 쌓고, 토픽별 마지막 payload를 보여주는 UI 로직
    // MainWindow 클래스의 일부로 정의
    public partial class MainWindow
    {
        // 선택된 토픽에 대해 아직 payload를 받은 적이 없을 때 표시할 텍스트
        private const string NoTopicDataText = "(no data yet)";

        // 클라이언트 토픽 ListBox에서 선택이 바뀌면 선택된 토픽의 마지막 메시지를 갱신
        private void ClientTopicListBox_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            UpdateSelectedTopicMessage(
                ClientTopicListBox, // 토픽 목록 ListBox
                _clientLastByTopic, // 토픽별 마지막 메시지 사전
                ClientLastMessageTextBox // 마지막 메시지 표시 TextBox
            );
        }

        // 브로커 토픽 ListBox에서 선택이 바뀌면 선택된 토픽의 마지막 메시지를 갱신한다
        private void TopicListBox_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            UpdateSelectedTopicMessage(TopicListBox, _brokerLastByTopic, BrokerDataTextBox);
        }

        // 브로커에서 메시지를 받았을 때 토픽/마지막 메시지 상태와 UI를 갱신
        private void OnBrokerMessageReceived(BrokerMessage msg)
        {
            UpdateTopicMessage(
                _brokerLastByTopic,
                _brokerTopics,
                TopicListBox,
                BrokerDataTextBox,
                msg.Topic,
                msg.PayloadText
            );
        }

        // 클라이언트에서 메시지를 받았을 때 토픽/마지막 메시지 상태와 UI를 갱신
        private void OnClientMessageReceived(PublisherMessage msg)
        {
            UpdateTopicMessage(
                _clientLastByTopic,
                _clientTopics,
                ClientTopicListBox,
                ClientLastMessageTextBox,
                msg.Topic,
                msg.PayloadText
            );
        }

        // topic의 마지막 payload를 저장
        // UI에서 토픽 목록을 업데이트하고 현재 선택된 토픽이면 상세 텍스트도 즉시 갱신
        private void UpdateTopicMessage(
            ConcurrentDictionary<string, string> lastByTopic, // 토픽별 마지막 메시지 딕셔너리
            ObservableCollection<string> topics, // 토픽 목록 컬렉션
            ListBox listBox, // 토픽 목록 ListBox
            TextBox lastMessageTextBox, // 마지막 메시지 표시 TextBox
            string topic, // 메시지 토픽
            string payloadText // 메시지 payload 텍스트
        )
        {
            // ConcurrentDictionary라 여러 스레드에서 동시에 들어와도 안전하게 갱신 가능
            lastByTopic[topic] = payloadText;

            // UI 갱신은 Dispatcher를 통해 UI 스레드에서 실행
            // WPF UI 컬렉션/컨트롤 접근은 UI 스레드에서 해야 안전
            Dispatcher.Invoke(() =>
            {
                // ObservableCollection은 UI 바인딩 시 리스트가 자동으로 갱신
                // 중복 토픽이 안 들어가게 Contains 체크 후 Add
                if (!topics.Contains(topic))
                    topics.Add(topic);

                // 지금 보고 있는 토픽에 새 메시지가 오면 화면도 바로 최신으로 갱신
                if (
                    listBox.SelectedItem is string selected
                    && string.Equals(selected, topic, StringComparison.Ordinal) // Ordinal 비교는 문자열을 정확히 비교한다
                )
                    lastMessageTextBox.Text = payloadText;
            });
        }

        // ListBox에서 선택된 토픽의 마지막 payload를 상세 TextBox에 표시
        private static void UpdateSelectedTopicMessage(
            ListBox listBox, // 토픽 목록 ListBox
            ConcurrentDictionary<string, string> lastByTopic, // 토픽별 마지막 메시지 딕셔너리
            TextBox lastMessageTextBox // 마지막 메시지 표시 TextBox
        )
        {
            // 선택된 항목이 문자열이 아니거나 빈 문자열이면 아무 것도 안 함
            if (listBox.SelectedItem is not string topic || string.IsNullOrWhiteSpace(topic))
                return;

            // 토픽의 최신 payload를 사용하거나, 없으면 일관된 placeholder를 사용
            lastMessageTextBox.Text = lastByTopic.TryGetValue(topic, out var payload)
                ? payload
                : NoTopicDataText;
        }
    }
}
