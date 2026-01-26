using System.Security.Cryptography.X509Certificates;

namespace MQTT_TLS_Bridge.Utils
{
    public static class CertUtil
    {
        public static X509Certificate2 LoadPkcs12FromFile(string pfxPath, string? password)
        {
            return X509CertificateLoader.LoadPkcs12FromFile(
                pfxPath,
                password,
                X509KeyStorageFlags.MachineKeySet | X509KeyStorageFlags.PersistKeySet,
                loaderLimits: null
            );
        }

        public static X509Certificate2 LoadPkcs12FromBytes(byte[] pfxBytes, string? password)
        {
            return X509CertificateLoader.LoadPkcs12(
                pfxBytes,
                password,
                X509KeyStorageFlags.MachineKeySet | X509KeyStorageFlags.PersistKeySet,
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
