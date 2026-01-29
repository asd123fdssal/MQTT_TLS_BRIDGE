namespace MQTT_TLS_Bridge.Broker
{
    // [접근 제한자 (Access Modifier)]
    // public: 다른 어셈블리에서도 접근 가능
    // internal: 같은 어셈블리 내에서만 접근 가능
    // private: 같은 클래스 내에서만 접근 가능
    // protected: 같은 클래스 및 파생 클래스에서 접근 가능
    // protected internal: 같은 어셈블리 내에서 또는 파생 클래스에서 접근 가능
    // private protected: 같은 클래스 내에서 또는 같은 어셈블리 내의 파생 클래스에서 접근 가능
    // 최상위 클래스에서 private/protected는 사용 불가

    // [클래스 수정자 (Class Modifiers)]
    // selaed: 이 클래스를 상속할 수 없도록 제한
    // abstract: 이 클래스는 인스턴스화할 수 없고 상속을 통해서만 사용 가능
    // static: 이 클래스는 인스턴스화할 수 없고 정적 멤버만 포함 가능 (유틸리티 클래스에 주로 사용)
    // partial: 이 클래스의 정의가 여러 파일에 걸쳐 있을 수 있음을 나타냄
    // unsafe: 이 클래스 내에서 포인터 연산을 허용

    // [변수 수정자 (Variable Modifiers)]
    // readonly: 변수는 선언 시 또는 생성자에서만 할당 가능하며 이후 변경 불가
    // const: 변수는 컴파일 타임에 값이 결정되며 이후 변경 불가 (정적 멤버로 간주됨)
    // volatile: 변수는 여러 스레드에서 동시에 접근할 수 있음을 나타내며, 컴파일러가 최적화 시 해당 변수를 캐싱하지 않도록 함
    // static: 변수는 클래스 수준에서 공유되며 인스턴스와 무관함
    // required: C# 11.0부터 도입된 기능으로, 객체 초기화 시 해당 속성에 반드시 값을 할당해야 함을 나타냄
    // init: C# 9.0부터 도입된 기능으로, 객체 초기화 시에만 속성 값을 설정할 수 있도록 허용하며 이후에는 변경 불가
    // nullable reference types: C# 8.0부터 도입된 기능으로, 참조 형식 변수가 null 값을 가질 수 있는지 여부를 명시적으로 지정 가능
    //     예: string? (null 허용), string (null 불허)
    //     예: List<string?> (리스트 내의 문자열이 null일 수 있음), List<string> (리스트 내의 문자열이 null일 수 없음)
    //     예: Dictionary<string, string?> (값이 null일 수 있음), Dictionary<string, string> (값이 null일 수 없음)
    //     예: Person? (Person 객체가 null일 수 있음), Person (Person 객체가 null일 수 없음)
    // var: 지역 변수 선언 시 사용되며, 컴파일러가 변수의 타입을 자동으로 추론함

    // 해당 클래스는 데이터 전달을 위한 DTO(Data Transfer Object) 역할
    // 상속이 불가능하도록 sealed 키워드 사용
    public sealed class BrokerMessage
    {
        // 아래 3개 항목은 반드시 설정되어야 함
        public required string Topic { get; init; }
        public required string PayloadText { get; init; }
        public required DateTime ReceivedAtUtc { get; init; }
    }
}
