param(
)

$BuildSourceDir = (Split-Path $PSScriptRoot -Parent)

$ErrorActionPreference = [System.Management.Automation.ActionPreference]::Ignore
Remove-Item -Recurse -Force "$BuildSourceDir\Build\Debug"
Remove-Item -Recurse -Force "$BuildSourceDir\Build\Release"
Remove-Item -Recurse -Force "$BuildSourceDir\obj"
Remove-Item -Force "$BuildSourceDir\KPScript.csproj.user"
Remove-Item -Force "$BuildSourceDir\KPScript.suo"
