using System.Net;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using MQTTnet.Server;
using MQTT_TLS_Bridge.Utils;

namespace MQTT_TLS_Bridge.Broker
{
    public sealed class MqttBrokerService : IAsyncDisposable
    {
        private MqttServer? _server;
        // Keep the loaded certificate around so we can dispose it with the broker server.
        private X509Certificate2? _certificate;

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
            cancellationToken.ThrowIfCancellationRequested();

            if (IsRunning)
            {
                WriteLog("Broker is already running.");
                return;
            }

            // Defensive cleanup in case a previous server was partially initialized.
            if (_server != null)
                DisposeServer();

            if (string.IsNullOrWhiteSpace(pfxPath))
                throw new InvalidOperationException("PFX path is empty.");

            var cert = CertUtil.LoadPkcs12FromFile(pfxPath, pfxPassword);

            if (!cert.HasPrivateKey)
            {
                cert.Dispose();
                throw new CryptographicException("PFX does not contain a private key.");
            }

            var rsa = cert.GetRSAPrivateKey();
            var ecdsa = cert.GetECDsaPrivateKey();
            if (rsa == null && ecdsa == null)
            {
                cert.Dispose();
                throw new CryptographicException(
                    "Private key is not accessible (RSA/ECDSA key is null)."
                );
            }

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
            _certificate = cert;
            RegisterServerEventHandlers(_server);

            try
            {
                cancellationToken.ThrowIfCancellationRequested();
                await _server.StartAsync();
            }
            catch
            {
                // Ensure server/cert resources are released if startup fails or is canceled.
                DisposeServer();
                throw;
            }

            WriteLog($"Broker started on mqtts://localhost:{port} ({sslProtocols}).");
        }

        public async Task StopAsync(CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();

            if (_server == null)
            {
                WriteLog("Broker is not initialized.");
                return;
            }

            if (!_server.IsStarted)
            {
                WriteLog("Broker is not running.");
                // Release any allocated resources even if the server is already stopped.
                DisposeServer();
                return;
            }

            await _server.StopAsync();
            WriteLog("Broker stopped.");
            DisposeServer();
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
                    DisposeServer();
                }
            }
        }

        private void DisposeServer()
        {
            if (_server != null)
            {
                try
                {
                    _server.Dispose();
                }
                finally
                {
                    _server = null;
                }
            }

            if (_certificate != null)
            {
                // Explicitly dispose the certificate to release native handles.
                _certificate.Dispose();
                _certificate = null;
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
                var payloadText = PayloadUtf8.Decode(e.ApplicationMessage.Payload);

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

        private void WriteLog(string message) => Log?.Invoke(message);
    }
}
