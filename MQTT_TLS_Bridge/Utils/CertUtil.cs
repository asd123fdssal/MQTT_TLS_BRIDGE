using System.Security.Cryptography.X509Certificates;

namespace MQTT_TLS_Bridge.Utils
{
    // CertUtil은 인증서 로딩을 한 곳으로 모아둔 유틸 클래스
    // PFX PKCS12 또는 일반 인증서 파일을 파일 경로나 바이트 배열에서 읽어 X509Certificate2로 반환
    // * 이 유틸이 반환하는 X509Certificate2는 네이티브 핸들을 가질 수 있으므로 사용 후 Dispose가 필요

    // 인스턴스를 만들지 않고 정적 메서드로만 사용하는 유틸 클래스
    public static class CertUtil
    {
        // PFX를 로드할 때 개인키를 어디에 어떻게 저장할지 지정하는 플래그
        // MachineKeySet: 사용자 개인 영역이 아니라 컴퓨터 단위 키 저장소를 사용
        //                서비스 계정이나 다른 사용자 컨텍스트에서도 키 접근이 필요한 경우에 유리
        // PersistKeySet: 로딩 시 개인키를 일회성으로만 쓰지 않고 저장소에 보존
        //                프로세스가 끝나도 키가 유지될 수 있음
        private const X509KeyStorageFlags DefaultKeyStorageFlags =
            X509KeyStorageFlags.MachineKeySet | X509KeyStorageFlags.PersistKeySet;

        // PFX PKCS12 파일을 경로에서 읽어서 X509Certificate2로 만듬
        public static X509Certificate2 LoadPkcs12FromFile(string pfxPath, string? password)
        {
            return X509CertificateLoader.LoadPkcs12FromFile(
                pfxPath,
                password,
                DefaultKeyStorageFlags,
                loaderLimits: null
            );
        }

        // PFX PKCS12 데이터를 바이트 배열에서 읽어서 X509Certificate2로 만듬
        public static X509Certificate2 LoadPkcs12FromBytes(byte[] pfxBytes, string? password)
        {
            return X509CertificateLoader.LoadPkcs12(
                pfxBytes,
                password,
                DefaultKeyStorageFlags,
                loaderLimits: null
            );
        }

        // 일반 인증서 파일을 경로에서 읽어서 X509Certificate2로 만듬
        public static X509Certificate2 LoadCertificateFromFile(string certPath)
        {
            return X509CertificateLoader.LoadCertificateFromFile(certPath);
        }

        // 일반 인증서 데이터를 바이트 배열에서 읽어서 X509Certificate2로 만듬
        public static X509Certificate2 LoadCertificateFromBytes(byte[] certBytes)
        {
            return X509CertificateLoader.LoadCertificate(certBytes);
        }
    }
}
