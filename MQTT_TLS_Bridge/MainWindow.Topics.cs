using System;
using System.Collections.Concurrent;
using System.Collections.ObjectModel;
using System.Windows.Controls;
using MQTT_TLS_Bridge.Broker;
using MQTT_TLS_Bridge.Publisher;

namespace MQTT_TLS_Bridge
{
    public partial class MainWindow
    {
        private void ClientTopicListBox_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            var topic = ClientTopicListBox.SelectedItem as string;
            if (string.IsNullOrWhiteSpace(topic))
                return;

            if (_clientLastByTopic.TryGetValue(topic, out var payload))
                ClientLastMessageTextBox.Text = payload;
            else
                ClientLastMessageTextBox.Text = "(no data yet)";
        }

        private void TopicListBox_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            var topic = TopicListBox.SelectedItem as string;
            if (string.IsNullOrWhiteSpace(topic))
                return;

            if (_brokerLastByTopic.TryGetValue(topic, out var payload))
                BrokerDataTextBox.Text = payload;
            else
                BrokerDataTextBox.Text = "(no data yet)";
        }

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

        private void UpdateTopicMessage(
            ConcurrentDictionary<string, string> lastByTopic,
            ObservableCollection<string> topics,
            ListBox listBox,
            TextBox lastMessageTextBox,
            string topic,
            string payloadText
        )
        {
            lastByTopic[topic] = payloadText;

            Dispatcher.Invoke(() =>
            {
                if (!topics.Contains(topic))
                    topics.Add(topic);

                if (
                    listBox.SelectedItem is string selected
                    && string.Equals(selected, topic, StringComparison.Ordinal)
                )
                    lastMessageTextBox.Text = payloadText;
            });
        }
    }
}
