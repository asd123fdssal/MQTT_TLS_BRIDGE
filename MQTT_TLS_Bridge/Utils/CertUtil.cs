using System.Security.Cryptography.X509Certificates;

namespace MQTT_TLS_Bridge.Utils
{
    public static class CertUtil
    {
        private const X509KeyStorageFlags DefaultKeyStorageFlags =
            X509KeyStorageFlags.MachineKeySet | X509KeyStorageFlags.PersistKeySet;

        public static X509Certificate2 LoadPkcs12FromFile(string pfxPath, string? password)
        {
            return X509CertificateLoader.LoadPkcs12FromFile(
                pfxPath,
                password,
                DefaultKeyStorageFlags,
                loaderLimits: null
            );
        }

        public static X509Certificate2 LoadPkcs12FromBytes(byte[] pfxBytes, string? password)
        {
            return X509CertificateLoader.LoadPkcs12(
                pfxBytes,
                password,
                DefaultKeyStorageFlags,
                loaderLimits: null
            );
        }

        public static X509Certificate2 LoadCertificateFromFile(string certPath)
        {
            return X509CertificateLoader.LoadCertificateFromFile(certPath);
        }

        public static X509Certificate2 LoadCertificateFromBytes(byte[] certBytes)
        {
            return X509CertificateLoader.LoadCertificate(certBytes);
        }
    }
}
