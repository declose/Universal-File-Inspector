# Builds UniversalFileInspector.exe into .\publish   (requires the .NET 10 SDK)
#
#   .\build.ps1                      single self-contained EXE (~100 MB, runs on any Windows 10/11 x64, no .NET needed)
#   .\build.ps1 -FrameworkDependent  small single EXE (<1 MB, needs the .NET 10 Desktop Runtime installed)
#
# Note: single-file compression is deliberately OFF. Windows Smart App Control blocks unsigned
# executables whose payload is compressed/packed, while the uncompressed bundle is allowed.
param([switch]$FrameworkDependent)
$ErrorActionPreference = 'Stop'
Set-Location $PSScriptRoot
$common = @('-c', 'Release', '-r', 'win-x64', '-p:PublishSingleFile=true', '-p:DebugType=none', '-p:DebugSymbols=false', '-o', 'publish')
if ($FrameworkDependent) {
    dotnet publish UniversalFileInspector.csproj @common --self-contained false
} else {
    dotnet publish UniversalFileInspector.csproj @common --self-contained true -p:EnableCompressionInSingleFile=false -p:IncludeNativeLibrariesForSelfExtract=true
}
if ($LASTEXITCODE -ne 0) { throw "publish failed" }
Get-Item publish\UniversalFileInspector.exe | Select-Object FullName, @{ n = 'SizeMB'; e = { [math]::Round($_.Length / 1MB, 1) } }
