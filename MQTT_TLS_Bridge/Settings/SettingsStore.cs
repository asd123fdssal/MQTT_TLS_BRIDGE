using System.IO;
using System.Text.Json;

namespace MQTT_TLS_Bridge.Settings
{
    // 앱 설정을 settings.json 파일로 저장/로드하는 유틸 클래스
    public static class SettingsStore
    {
        private const string ConfigFolderName = "Config";
        private const string FileName = "settings.json";

        // 설정 파일의 전체 경로를 반환
        public static string SettingsPath
        {
            get
            {
                // 앱 실행 파일이 있는 기본 폴더(AppContext.BaseDirectory) 아래에 Config 폴더를 만든다
                var dir = Path.Combine(AppContext.BaseDirectory, ConfigFolderName);
                return Path.Combine(dir, FileName);
            }
        }

        // SettingsPath에 해당 파일이 있으면 true, 없으면 false
        public static bool Exists() => File.Exists(SettingsPath);

        // JSON 저장 시 보기 좋게 들여쓰기(Pretty print) 옵션을 사용한다
        private static readonly JsonSerializerOptions JsonIndentedOptions = new()
        {
            WriteIndented = true,
        };

        // AppSettings를 JSON으로 직렬화해서 settings.json에 저장
        public static void Save(AppSettings settings)
        {
            // settings.json이 들어갈 폴더 경로를 구하고 폴더가 없어도 예외 없이 생성
            var dir = Path.GetDirectoryName(SettingsPath)!;
            Directory.CreateDirectory(dir);

            // 수동으로 확인하기 쉽도록 들여쓰기 포함 형태로 저장
            // settings 객체를 들여쓰기 옵션으로 JSON 문자열로 만든뒤 파일로 저장
            var json = JsonSerializer.Serialize(settings, JsonIndentedOptions);

            File.WriteAllText(SettingsPath, json);
        }

        // settings.json을 읽어서 AppSettings로 역직렬화
        public static AppSettings Load()
        {
            // 설정 파일이 없으면 예외를 던져 실패 처리
            var path = SettingsPath;
            if (!File.Exists(path))
                throw new FileNotFoundException("Settings file not found.", path);

            // 파일 내용을 문자열로 변환
            var json = File.ReadAllText(path);

            // JSON을 AppSettings로 변환
            // JSON에 Client/Broker가 없을 수도 있으니 null이면 기본 객체를 생성
            var settings =
                JsonSerializer.Deserialize<AppSettings>(json)
                ?? throw new InvalidOperationException("Settings file is invalid.");
            settings.Client ??= new ClientSettings();
            settings.Broker ??= new BrokerSettings();

            // 비밀번호 저장 옵션이 꺼져 있으면 비밀번호를 null로 설정
            if (!settings.SavePasswords)
            {
                settings.Client.Password = null;
                settings.Broker.PfxPassword = null;
            }

            return settings;
        }
    }
}
