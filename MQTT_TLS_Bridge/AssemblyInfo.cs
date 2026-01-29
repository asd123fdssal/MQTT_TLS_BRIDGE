using System.Windows;

// 이 설정이 클래스가 아니라 프로젝트(어셈블리) 전체에 적용
[assembly: ThemeInfo(
    ResourceDictionaryLocation.None, // 테마별 리소스 딕셔너리를 별도로 제공하지 않는다
    //where theme specific resource dictionaries are located
    //(used if a resource is not found in the page,
    // or application resource dictionaries)
    ResourceDictionaryLocation.SourceAssembly // 테마별 리소스가 없거나 못 찾았을 때 사용할 기본 리소스가 현재 어셈블리 안에 있다
//where the generic resource dictionary is located
//(used if a resource is not found in the page,
// app, or any theme specific resource dictionaries)
)]
