using System.Security.Authentication;
using MQTT_TLS_Bridge.Enums;
using MQTT_TLS_Bridge.Utils;
using MQTTnet;
using MQTTnet.Protocol;

namespace MQTT_TLS_Bridge.Publisher
{
    public sealed class MqttPublisherService : IAsyncDisposable
    {
        private IMqttClient? _client;

        private Func<MqttClientConnectedEventArgs, Task>? _onConnected;
        private Func<MqttClientDisconnectedEventArgs, Task>? _onDisconnected;
        private Func<MqttApplicationMessageReceivedEventArgs, Task>? _onMessageReceived;

        public bool IsConnected => _client?.IsConnected == true;

        public event Action<string>? Log;
        public event Action<ConnectionState, string?>? ConnectionStateChanged;
        public event Action<PublisherMessage>? MessageReceived;

        public async Task ConnectAsync(
            PublisherConnectionSettings settings,
            CancellationToken cancellationToken
        )
        {
            cancellationToken.ThrowIfCancellationRequested();

            if (IsConnected)
            {
                WriteLog("Client already connected.");
                return;
            }

            SetState(ConnectionState.Connecting, null);

            ResetClient();

            _client = CreateClient();
            RegisterClientEventHandlers(_client);

            var options = BuildOptions(settings);

            await DoConnectAsync(_client, options, cancellationToken);

            SetState(ConnectionState.Connected, null);
            WriteLog("Client connected.");
        }

        public async Task DisconnectAsync(CancellationToken cancellationToken)
        {
            if (_client == null)
            {
                SetState(ConnectionState.Disconnected, null);
                return;
            }

            try
            {
                if (_client.IsConnected)
                    await _client.DisconnectAsync(cancellationToken: cancellationToken);
            }
            finally
            {
                SetState(ConnectionState.Disconnected, null);
                WriteLog("Client disconnected.");
            }
        }

        public async Task PublishAsync(
            string topic,
            string payloadText,
            bool retain,
            MqttQualityOfServiceLevel qos,
            CancellationToken cancellationToken
        )
        {
            EnsureConnected();

            var msg = new MqttApplicationMessageBuilder()
                .WithTopic(topic)
                .WithPayload(payloadText ?? string.Empty)
                .WithRetainFlag(retain)
                .WithQualityOfServiceLevel(qos)
                .Build();

            await _client!.PublishAsync(msg, cancellationToken);
            WriteLog($"Published: Topic={topic}, QoS={qos}, Retain={retain}");
        }

        public async Task SubscribeAsync(
            string topic,
            MqttQualityOfServiceLevel qos,
            CancellationToken cancellationToken
        )
        {
            EnsureConnected();

            var filter = new MqttTopicFilterBuilder()
                .WithTopic(topic)
                .WithQualityOfServiceLevel(qos)
                .Build();

            await _client!.SubscribeAsync(filter, cancellationToken);
            WriteLog($"Subscribed: {topic} (QoS={qos})");
        }

        public async Task UnsubscribeAsync(string topicFilter, CancellationToken cancellationToken)
        {
            EnsureConnected();

            if (string.IsNullOrWhiteSpace(topicFilter))
                throw new InvalidOperationException("Topic filter is empty.");

            await _client!.UnsubscribeAsync(topicFilter, cancellationToken);
            WriteLog($"Unsubscribed: {topicFilter}");
        }

        public async ValueTask DisposeAsync()
        {
            if (_client == null)
                return;

            try
            {
                if (_client.IsConnected)
                    await _client.DisconnectAsync();
            }
            finally
            {
                UnregisterClientEventHandlers(_client);
                _client.Dispose();
                _client = null;
            }
        }

        private static IMqttClient CreateClient()
        {
            var factory = new MqttClientFactory();
            return factory.CreateMqttClient();
        }

        private void ResetClient()
        {
            if (_client == null)
                return;

            try
            {
                UnregisterClientEventHandlers(_client);
                _client.Dispose();
            }
            finally
            {
                _client = null;
            }
        }

        private static MqttClientOptions BuildOptions(PublisherConnectionSettings settings)
        {
            var tlsBuilder = new MqttClientTlsOptionsBuilder()
                .UseTls(settings.UseTls)
                .WithSslProtocols(settings.SslProtocols);

            if (settings.AllowUntrustedCertificates)
            {
                tlsBuilder = tlsBuilder
                    .WithAllowUntrustedCertificates(true)
                    .WithIgnoreCertificateChainErrors(true)
                    .WithIgnoreCertificateRevocationErrors(true)
                    .WithCertificateValidationHandler(_ => true);
            }

            var tls = tlsBuilder.Build();

            var optionsBuilder = new MqttClientOptionsBuilder()
                .WithTcpServer(settings.Host, settings.Port)
                .WithClientId(settings.ClientId)
                .WithTlsOptions(tls);

            if (!string.IsNullOrWhiteSpace(settings.Username))
                optionsBuilder = optionsBuilder.WithCredentials(
                    settings.Username,
                    settings.Password
                );

            return optionsBuilder.Build();
        }

        private async Task DoConnectAsync(
            IMqttClient client,
            MqttClientOptions options,
            CancellationToken ct
        )
        {
            try
            {
                var result = await client.ConnectAsync(options, ct);

                if (result.ResultCode != MqttClientConnectResultCode.Success)
                {
                    var reason = string.IsNullOrWhiteSpace(result.ReasonString)
                        ? result.ResultCode.ToString()
                        : result.ReasonString;

                    SetState(ConnectionState.Error, reason);
                    WriteLog($"Connect rejected: {reason}");
                    throw new InvalidOperationException($"Connect rejected: {reason}");
                }
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested)
            {
                SetState(ConnectionState.Disconnected, "Canceled");
                WriteLog("Connect canceled.");
                throw;
            }
            catch (Exception ex)
            {
                SetState(ConnectionState.Error, ex.Message);
                WriteLog($"Connect failed: {ex.GetType().Name}: {ex.Message}");
                throw;
            }
        }

        private void RegisterClientEventHandlers(IMqttClient client)
        {
            _onConnected ??= OnConnectedAsync;
            _onDisconnected ??= OnDisconnectedAsync;
            _onMessageReceived ??= OnMessageReceivedAsync;

            client.ConnectedAsync += _onConnected;
            client.DisconnectedAsync += _onDisconnected;
            client.ApplicationMessageReceivedAsync += _onMessageReceived;
        }

        private void UnregisterClientEventHandlers(IMqttClient client)
        {
            if (_onConnected != null)
                client.ConnectedAsync -= _onConnected;
            if (_onDisconnected != null)
                client.DisconnectedAsync -= _onDisconnected;
            if (_onMessageReceived != null)
                client.ApplicationMessageReceivedAsync -= _onMessageReceived;
        }

        private Task OnConnectedAsync(MqttClientConnectedEventArgs e)
        {
            WriteLog("Connected event received.");
            return Task.CompletedTask;
        }

        private Task OnDisconnectedAsync(MqttClientDisconnectedEventArgs e)
        {
            var msg = e.Exception != null ? e.Exception.Message : e.Reason.ToString();
            WriteLog($"Disconnected event received: {msg}");

            if (!IsConnected)
                SetState(ConnectionState.Disconnected, msg);

            return Task.CompletedTask;
        }

        private Task OnMessageReceivedAsync(MqttApplicationMessageReceivedEventArgs e)
        {
            var topic = e.ApplicationMessage.Topic;
            var payloadText = PayloadUtf8.Decode(e.ApplicationMessage.Payload);

            MessageReceived?.Invoke(
                new PublisherMessage
                {
                    Topic = topic,
                    PayloadText = payloadText,
                    ReceivedAtUtc = DateTime.UtcNow,
                }
            );

            WriteLog($"Received: Topic={topic}");
            return Task.CompletedTask;
        }

        private void EnsureConnected()
        {
            if (_client == null || !_client.IsConnected)
                throw new InvalidOperationException("Client is not connected.");
        }

        private void WriteLog(string message) => Log?.Invoke(message);

        private void SetState(ConnectionState state, string? detail) =>
            ConnectionStateChanged?.Invoke(state, detail);
    }
}
