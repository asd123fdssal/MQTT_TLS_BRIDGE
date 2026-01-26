using System.Buffers;
using System.Net;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using MQTTnet.Server;

namespace MQTT_TLS_Bridge.Broker
{
    public sealed class MqttBrokerService : IAsyncDisposable
    {
        private MqttServer? _server;

        public bool IsRunning => _server?.IsStarted == true;

        public event Action<string>? Log;
        public event Action<BrokerMessage>? MessageReceived;

        public async Task StartAsync(
            string pfxPath,
            string pfxPassword,
            int port,
            SslProtocols sslProtocols,
            CancellationToken cancellationToken
        )
        {
            if (IsRunning)
            {
                WriteLog("Broker is already running.");
                return;
            }

            if (string.IsNullOrWhiteSpace(pfxPath))
                throw new InvalidOperationException("PFX path is empty.");

            var cert = X509CertificateLoader.LoadPkcs12FromFile(
                pfxPath,
                pfxPassword,
                X509KeyStorageFlags.MachineKeySet | X509KeyStorageFlags.PersistKeySet,
                loaderLimits: null
            );

            if (!cert.HasPrivateKey)
                throw new CryptographicException("PFX does not contain a private key.");

            var rsa = cert.GetRSAPrivateKey();
            var ecdsa = cert.GetECDsaPrivateKey();
            if (rsa == null && ecdsa == null)
                throw new CryptographicException(
                    "Private key is not accessible (RSA/ECDSA key is null)."
                );

            var serverFactory = new MqttServerFactory();

            var options = serverFactory
                .CreateServerOptionsBuilder()
                .WithoutDefaultEndpoint()
                .WithEncryptedEndpoint()
                .WithEncryptedEndpointBoundIPAddress(IPAddress.Any)
                .WithEncryptedEndpointPort(port)
                .WithEncryptionCertificate(cert)
                .WithEncryptionSslProtocol(sslProtocols)
                .Build();

            _server = serverFactory.CreateMqttServer(options);
            RegisterServerEventHandlers(_server);

            await _server.StartAsync();

            WriteLog($"Broker started on mqtts://localhost:{port} ({sslProtocols}).");
        }

        public async Task StopAsync(CancellationToken cancellationToken)
        {
            if (_server == null)
            {
                WriteLog("Broker is not initialized.");
                return;
            }

            if (!_server.IsStarted)
            {
                WriteLog("Broker is not running.");
                return;
            }

            await _server.StopAsync();
            WriteLog("Broker stopped.");
        }

        public async ValueTask DisposeAsync()
        {
            if (_server != null)
            {
                try
                {
                    if (_server.IsStarted)
                        await _server.StopAsync();
                }
                finally
                {
                    _server.Dispose();
                    _server = null;
                }
            }
        }

        private void RegisterServerEventHandlers(MqttServer server)
        {
            server.ClientConnectedAsync += e =>
            {
                WriteLog($"Client connected: {e.ClientId}");
                return Task.CompletedTask;
            };

            server.ClientDisconnectedAsync += e =>
            {
                WriteLog($"Client disconnected: {e.ClientId}, Type={e.DisconnectType}");
                return Task.CompletedTask;
            };

            server.InterceptingPublishAsync += e =>
            {
                var topic = e.ApplicationMessage.Topic;
                var payloadText = DecodePayloadAsUtf8(e.ApplicationMessage.Payload);

                MessageReceived?.Invoke(
                    new BrokerMessage
                    {
                        Topic = topic,
                        PayloadText = payloadText,
                        ReceivedAtUtc = DateTime.UtcNow,
                    }
                );

                WriteLog($"Publish intercepted: ClientId={e.ClientId}, Topic={topic}");
                return Task.CompletedTask;
            };
        }

        private static string DecodePayloadAsUtf8(ReadOnlySequence<byte> payload)
        {
            if (payload.IsEmpty)
                return "(empty)";

            if (payload.IsSingleSegment)
                return Encoding.UTF8.GetString(payload.FirstSpan);

            return Encoding.UTF8.GetString(payload.ToArray());
        }

        private void WriteLog(string message) => Log?.Invoke(message);
    }
}
