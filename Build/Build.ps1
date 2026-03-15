param(
    [string]$Configuration = "Release",
	[switch]$Debug = $False,
	[switch]$Release = $False,
	[string]$DotNetVersion = ""
)

$BuildSourceDir = (Split-Path $PSScriptRoot -Parent)
if ($Release) { $Configuration = "Release" }
if ($Debug) { $Configuration = "Debug" }

if ($DotNetVersion) {
	$DotNetVersion = Get-ChildItem "$env:SystemRoot\Microsoft.NET\Framework" `
				-Name $DotNetVersion | Select-Object -First 1
	$DotNetDir = "$env:SystemRoot\Microsoft.NET\Framework\$DotNetVersion"
} elseif (Get-Command MSBuild.exe -ErrorAction 0 | Out-Null) {
	$DotNetDir = "."
} else {
	$DotNetVersion = @( foreach ($vglob in @("v3.5","v4.*")) {
		Get-ChildItem "$env:SystemRoot\Microsoft.NET\Framework" -Name $vglob
	} ) | Select-Object -First 1
	$DotNetDir = "$env:SystemRoot\Microsoft.NET\Framework\$DotNetVersion"
}

Start-Job -ArgumentList @(
	$BuildSourceDir,
	$DotNetDir,
	$Configuration
) -ScriptBlock {
param(
	[string]$BuildSourceDir,
	[string]$DotNetDir,
	[string]$Configuration
)

cd "$DotNetDir"
& "$DotNetDir\MSBuild.exe" "$BuildSourceDir\KPScript.sln" "/property:Configuration=$Configuration"

} | Receive-Job -Wait -AutoRemoveJob
