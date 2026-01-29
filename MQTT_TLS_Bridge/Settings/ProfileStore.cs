using System.Globalization;
using System.IO;
using System.Text;
using System.Windows.Input;

namespace MQTT_TLS_Bridge.Settings
{
    // INI 파일 기반으로 AppSettings를 저장/불러오기 하는 저장소
    // 로드 시 default.ini를 먼저 적용하고, 프로필 ini가 있으면 추가로 덮어써서 최종 설정을 적용
    public static class IniProfileStore
    {
        // 설정 파일이 들어있는 폴더 경로
        private static readonly string ConfigDir = Path.Combine(
            AppDomain.CurrentDomain.BaseDirectory, // 현재 실행 파일이 있는 폴더
            "Config" // Config 폴더
        );
        private static readonly string ProfilesDir = Path.Combine(ConfigDir, "profiles"); // profiles 폴더
        private static readonly string DefaultPath = Path.Combine(ConfigDir, "default.ini"); // default.ini 경로

        private const string SectionMeta = "Meta"; // 메타 정보 섹션
        private const string SectionBroker = "Broker"; // 브로커 설정 섹션
        private const string SectionClient = "Client"; // 클라이언트 설정 섹션

        // 키 이름을 정규화한 후 해당 키에 대한 설정 적용 액션 매핑
        private static readonly Dictionary<string, Action<AppSettings, string>> Appliers =
            BuildAppliers();

        // Config\profiles 폴더에서 .ini 파일 목록을 찾아 프로필 이름 리스트를 반환
        public static List<string> ListProfiles()
        {
            try
            {
                // profiles 폴더가 없으면 프로필이 없다고 보고 빈 리스트 반환
                if (!Directory.Exists(ProfilesDir))
                    return [];

                return
                [
                    .. Directory
                        .EnumerateFiles(ProfilesDir, "*.ini", SearchOption.TopDirectoryOnly) // profiles 폴더의 ini 파일만 나열
                        .Select(Path.GetFileNameWithoutExtension) // 확장자 제거한 이름만 추출
                        .Where(n => !string.IsNullOrWhiteSpace(n)) // 빈 이름 제거
                        .Select(n => n!) // null 아님
                        .OrderBy(n => n, StringComparer.OrdinalIgnoreCase), // 대소문자 무시 정렬
                ];
            }
            catch
            {
                return []; // 디렉토리 접근 실패 등 예외 시 안전하게 빈 리스트 반환
            }
        }

        // 실행에 사용할 최종 설정을 만듬
        public static AppSettings LoadEffective(string? profileName)
        {
            // 실행에 사용할 최종 설정을 생성
            var settings = new AppSettings();

            // default.ini가 있으면 읽어서 settings에 반영
            ApplyIniFileIfExists(settings, DefaultPath);

            // 프로필 이름이 있으면 프로필 ini를 적용
            // 같은 키가 있으면 프로필 값이 default 값을 덮어씀
            if (!string.IsNullOrWhiteSpace(profileName))
                ApplyIniFileIfExists(settings, GetProfilePath(profileName));

            return settings;
        }

        // 현재 설정을 default.ini에 저장
        public static void SaveDefault(AppSettings settings)
        {
            // Config 폴더가 없으면 생성
            Directory.CreateDirectory(ConfigDir);
            // 설정을 INI 텍스트로 만들어 default.ini로 저장
            WriteIni(settings, DefaultPath);
        }

        // 지정한 profileName으로 profiles\<name>.ini에 저장
        public static void SaveProfile(string profileName, AppSettings settings)
        {
            // 프로필 이름이 비어 있으면 저장 불가, 예외 던짐
            if (string.IsNullOrWhiteSpace(profileName))
                throw new InvalidOperationException("profile name is empty.");

            // profiles 폴더 생성 후 저장
            Directory.CreateDirectory(ProfilesDir);
            WriteIni(settings, GetProfilePath(profileName));
        }

        // AppSettings를 "client.host", "broker.port" 같은 단일 딕셔너리 형태로 변환
        // 숫자는 로케일 영향 없이 문자열로 만들고, bool은 1/0으로 저장
        public static Dictionary<string, string> Flatten(AppSettings settings)
        {
            // 키를 대소문자 무시로 관리
            var dict = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
            {
                ["savePasswords"] = settings.SavePasswords ? "1" : "0",

                ["client.host"] = settings.Client.Host ?? string.Empty,
                ["client.port"] = settings.Client.Port.ToString(CultureInfo.InvariantCulture),
                ["client.clientId"] = settings.Client.ClientId ?? string.Empty,
                ["client.username"] = settings.Client.Username ?? string.Empty,
                ["client.password"] = settings.Client.Password ?? string.Empty,
                ["client.useTls"] = settings.Client.UseTls ? "1" : "0",
                ["client.allowUntrusted"] = settings.Client.AllowUntrustedCertificates ? "1" : "0",
                ["client.sslProtocolsIndex"] = settings.Client.SslProtocolsIndex.ToString(
                    CultureInfo.InvariantCulture
                ),
                ["client.validationModeIndex"] = settings.Client.ValidationModeIndex.ToString(
                    CultureInfo.InvariantCulture
                ),
                ["client.caCertificatePath"] = settings.Client.CaCertificatePath ?? string.Empty,
                ["client.pinnedThumbprint"] = settings.Client.PinnedThumbprint ?? string.Empty,

                ["client.subTopicFilter"] = settings.Client.SubTopicFilter ?? string.Empty,
                ["client.subQosIndex"] = settings.Client.SubQosIndex.ToString(
                    CultureInfo.InvariantCulture
                ),

                ["client.pubTopic"] = settings.Client.PubTopic ?? string.Empty,
                ["client.pubPayload"] = settings.Client.PubPayload ?? string.Empty,
                ["client.pubQosIndex"] = settings.Client.PubQosIndex.ToString(
                    CultureInfo.InvariantCulture
                ),
                ["client.pubRetain"] = settings.Client.PubRetain ? "1" : "0",

                ["broker.port"] = settings.Broker.Port.ToString(CultureInfo.InvariantCulture),
                ["broker.pfxPath"] = settings.Broker.PfxPath ?? string.Empty,
                ["broker.pfxPassword"] = settings.Broker.PfxPassword ?? string.Empty,
                ["broker.sslProtocolsIndex"] = settings.Broker.SslProtocolsIndex.ToString(
                    CultureInfo.InvariantCulture
                ),
            };

            return dict;
        }

        // patch 딕셔너리의 key/value를 AppSettings target에 반영
        public static void ApplyPatch(AppSettings target, IReadOnlyDictionary<string, string> patch)
        {
            // patch의 모든 항목을 순회
            foreach (var kv in patch)
            {
                // 공백/Null 방어 + trim
                // key가 비면 무시
                var key = (kv.Key ?? string.Empty).Trim();
                if (key.Length == 0)
                    continue;

                var value = (kv.Value ?? string.Empty).Trim();

                // 키를 소문자 등으로 정규화
                // 등록된 applier가 있으면 settings에 실제로 반영
                var normalizedKey = NormalizeKey(key);

                if (Appliers.TryGetValue(normalizedKey, out var apply))
                    apply(target, value);
            }
        }

        // INI 파일이 존재하면 읽어서 patch로 만들고 settings에 적용
        private static void ApplyIniFileIfExists(AppSettings settings, string path)
        {
            // 파일 없으면 아무 것도 하지 않음
            if (!File.Exists(path))
                return;

            // INI 파일을 읽어서 단일 딕셔너리 형태의 패치로 변환
            var patch = ReadIniAsPatch(path);
            ApplyPatch(settings, patch);
        }

        // profileName을 파일명으로 안전하게 만든 뒤 profiles\<safe>.ini 경로를 반환
        private static string GetProfilePath(string profileName)
        {
            // 파일명에 쓸 수 없는 문자를 _로 치환해 경로 조작/오류를 방지
            var safe = profileName.Trim();

            foreach (var c in Path.GetInvalidFileNameChars())
                safe = safe.Replace(c, '_');

            return Path.Combine(ProfilesDir, safe + ".ini");
        }

        // INI 파일을 읽어서 "Section.key" = "value" 형태의 patch 딕셔너리로 치환
        private static Dictionary<string, string> ReadIniAsPatch(string path)
        {
            // 결과 patch와 현재 섹션명 초기화
            var patch = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            var section = string.Empty;

            // UTF8로 모든 줄을 읽음
            foreach (var raw in File.ReadAllLines(path, Encoding.UTF8))
            {
                // 빈 줄/주석 줄 무시
                var line = (raw ?? string.Empty).Trim();
                if (line.Length == 0)
                    continue;

                if (line.StartsWith(';') || line.StartsWith('#'))
                    continue;

                // [Section] 형태면 section 갱신
                if (TryReadSection(line, out var newSection))
                {
                    section = newSection;
                    continue;
                }

                // key=value면 section을 붙여 dotted key 생성
                // 같은 키가 여러 번 나오면 마지막 값으로 덮어씀
                if (!TryReadKeyValue(line, out var key, out var value))
                    continue;

                var dotted = section.Length == 0 ? key : (section + "." + key);
                patch[dotted] = value;
            }

            return patch;
        }

        // 한 줄이 [Section] 형식인지 판단하고 섹션명을 추출
        private static bool TryReadSection(string line, out string section)
        {
            section = string.Empty;

            // 대괄호로 감싸져 있어야 섹션
            if (!line.StartsWith('[') || !line.EndsWith(']'))
                return false;

            // 괄호 내부를 trim해 섹션명으로 사용
            section = line[1..^1].Trim();
            return true;
        }

        // 한 줄이 key=value 형식인지 판단하고 key/value를 추출
        private static bool TryReadKeyValue(string line, out string key, out string value)
        {
            key = string.Empty;
            value = string.Empty;

            // '='가 없거나 맨 앞이면 실패
            // key는 trim 후 비면 실패
            // value는 '=' 이후를 trim
            var idx = line.IndexOf('=');
            if (idx <= 0)
                return false;

            key = line[..idx].Trim();
            if (key.Length == 0)
                return false;

            value = line[(idx + 1)..].Trim();
            return true;
        }

        // AppSettings 값을 INI 텍스트 형식으로 만들어 파일로 저장
        private static void WriteIni(AppSettings settings, string path)
        {
            // INI 내용을 누적해서 만들기 위한 버퍼
            var sb = new StringBuilder();

            // Meta 섹션 작성
            sb.AppendLine("[" + SectionMeta + "]");
            sb.AppendLine("savePasswords=" + (settings.SavePasswords ? "1" : "0"));
            sb.AppendLine();

            // Broker 섹션 작성
            sb.AppendLine("[" + SectionBroker + "]");
            sb.AppendLine("port=" + settings.Broker.Port.ToString(CultureInfo.InvariantCulture)); // 숫자는 InvariantCulture로 저장해서 로케일 영향 제거
            sb.AppendLine("pfxPath=" + (settings.Broker.PfxPath ?? string.Empty));
            sb.AppendLine("pfxPassword=" + (settings.Broker.PfxPassword ?? string.Empty));
            sb.AppendLine(
                "sslProtocolsIndex="
                    + settings.Broker.SslProtocolsIndex.ToString(CultureInfo.InvariantCulture)
            );
            sb.AppendLine();

            // Client 섹션 작성
            sb.AppendLine("[" + SectionClient + "]");
            sb.AppendLine("host=" + (settings.Client.Host ?? string.Empty));
            sb.AppendLine("port=" + settings.Client.Port.ToString(CultureInfo.InvariantCulture));
            sb.AppendLine("clientId=" + (settings.Client.ClientId ?? string.Empty));
            sb.AppendLine("username=" + (settings.Client.Username ?? string.Empty));
            sb.AppendLine("password=" + (settings.Client.Password ?? string.Empty));
            sb.AppendLine("useTls=" + (settings.Client.UseTls ? "1" : "0"));
            sb.AppendLine(
                "allowUntrusted=" + (settings.Client.AllowUntrustedCertificates ? "1" : "0")
            );
            sb.AppendLine(
                "sslProtocolsIndex="
                    + settings.Client.SslProtocolsIndex.ToString(CultureInfo.InvariantCulture)
            );
            sb.AppendLine(
                "validationModeIndex="
                    + settings.Client.ValidationModeIndex.ToString(CultureInfo.InvariantCulture)
            );
            sb.AppendLine(
                "caCertificatePath=" + (settings.Client.CaCertificatePath ?? string.Empty)
            );
            sb.AppendLine("pinnedThumbprint=" + (settings.Client.PinnedThumbprint ?? string.Empty));
            sb.AppendLine("subTopicFilter=" + (settings.Client.SubTopicFilter ?? string.Empty));
            sb.AppendLine(
                "subQosIndex=" + settings.Client.SubQosIndex.ToString(CultureInfo.InvariantCulture)
            );
            sb.AppendLine("pubTopic=" + (settings.Client.PubTopic ?? string.Empty));
            sb.AppendLine("pubPayload=" + (settings.Client.PubPayload ?? string.Empty));
            sb.AppendLine(
                "pubQosIndex=" + settings.Client.PubQosIndex.ToString(CultureInfo.InvariantCulture)
            );
            sb.AppendLine("pubRetain=" + (settings.Client.PubRetain ? "1" : "0"));
            sb.AppendLine();

            // UTF8로 INI 파일을 저장
            File.WriteAllText(path, sb.ToString(), Encoding.UTF8);
        }

        // INI에서 읽어온 patch key/value를 AppSettings에 반영하기 위한 키 → 적용 함수 맵을 만듬
        // 키 별칭(alias)을 같이 등록해 다양한 키 이름을 허용
        private static Dictionary<string, Action<AppSettings, string>> BuildAppliers()
        {
            // key는 대소문자 무시
            // value는 문자열이므로 ParseBool/ TryParseInt로 파싱해서 설정에 반영
            var map = new Dictionary<string, Action<AppSettings, string>>(
                StringComparer.OrdinalIgnoreCase
            )
            {
                ["savepasswords"] = (t, v) => t.SavePasswords = ParseBool(v, t.SavePasswords),
            };
            map["meta.savepasswords"] = map["savepasswords"];

            // Broker 항목 적용자 등록
            // 숫자는 파싱 성공했을 때만 반영
            // 문자열은 그대로 반영
            map["broker.port"] = (t, v) =>
            {
                if (TryParseInt(v, out var p))
                    t.Broker.Port = p;
            };

            map["broker.pfxpath"] = (t, v) => t.Broker.PfxPath = v;
            map["broker.pfxpassword"] = (t, v) => t.Broker.PfxPassword = v;

            map["broker.sslprotocolsindex"] = (t, v) =>
            {
                if (TryParseInt(v, out var idx))
                    t.Broker.SslProtocolsIndex = idx;
            };

            // Client 항목 적용자 등록
            // bool은 ParseBool로 변환하고 실패하면 기존값 유지
            // index는 TryParseInt 성공 시만 반영
            map["client.host"] = (t, v) => t.Client.Host = v;

            map["client.port"] = (t, v) =>
            {
                if (TryParseInt(v, out var p))
                    t.Client.Port = p;
            };

            map["client.clientid"] = (t, v) => t.Client.ClientId = v;
            map["client.username"] = (t, v) => t.Client.Username = v;
            map["client.password"] = (t, v) => t.Client.Password = v;

            map["client.usetls"] = (t, v) => t.Client.UseTls = ParseBool(v, t.Client.UseTls);

            map["client.allowuntrusted"] = (t, v) =>
                t.Client.AllowUntrustedCertificates = ParseBool(
                    v,
                    t.Client.AllowUntrustedCertificates
                );
            map["client.allowuntrustedcertificates"] = map["client.allowuntrusted"];

            map["client.sslprotocolsindex"] = (t, v) =>
            {
                if (TryParseInt(v, out var idx))
                    t.Client.SslProtocolsIndex = idx;
            };

            map["client.validationmodeindex"] = (t, v) =>
            {
                if (TryParseInt(v, out var idx))
                    t.Client.ValidationModeIndex = idx;
            };

            map["client.cacertificatepath"] = (t, v) => t.Client.CaCertificatePath = v;
            map["client.capath"] = map["client.cacertificatepath"];

            map["client.pinnedthumbprint"] = (t, v) => t.Client.PinnedThumbprint = v;
            map["client.thumbprint"] = map["client.pinnedthumbprint"];

            map["client.subtopicfilter"] = (t, v) => t.Client.SubTopicFilter = v;

            map["client.subqosindex"] = (t, v) =>
            {
                if (TryParseInt(v, out var idx))
                    t.Client.SubQosIndex = idx;
            };

            map["client.pubtopic"] = (t, v) => t.Client.PubTopic = v;
            map["client.pubpayload"] = (t, v) => t.Client.PubPayload = v;

            map["client.pubqosindex"] = (t, v) =>
            {
                if (TryParseInt(v, out var idx))
                    t.Client.PubQosIndex = idx;
            };

            map["client.pubretain"] = (t, v) =>
                t.Client.PubRetain = ParseBool(v, t.Client.PubRetain);

            return map;
        }

        // patch key를 비교하기 쉬운 형태로 정규화
        private static string NormalizeKey(string key)
        {
            // 빈 키는 빈 문자열로 그 외는 소문자로 통일
            var k = (key ?? string.Empty).Trim();

            if (k.Length == 0)
                return string.Empty;

            return k.ToLowerInvariant();
        }

        // 문자열을 bool로 해석
        // 해석 불가하면 defaultValue를 그대로 반환
        private static bool ParseBool(string text, bool defaultValue)
        {
            var v = (text ?? string.Empty).Trim().ToLowerInvariant();
            return v switch
            {
                "1" => true,
                "0" => false,
                "true" => true,
                "false" => false,
                "yes" => true,
                "no" => false,
                _ => defaultValue,
            };
        }

        // 문자열을 int로 파싱한다 로케일 영향 없이 InvariantCulture 기준으로 파싱
        private static bool TryParseInt(string text, out int value)
        {
            // 공백 제거 후 정수 파싱 실패하면 false 반환, value는 out 규칙대로 기본값
            return int.TryParse(
                (text ?? string.Empty).Trim(),
                NumberStyles.Integer,
                CultureInfo.InvariantCulture,
                out value
            );
        }
    }
}
