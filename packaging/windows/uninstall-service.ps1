# OpenAudit Agent Windows Service Uninstallation Script
# Run with elevated Administrator privileges

param (
    [string]$ServiceName = "OpenAuditAgent"
)

$ErrorActionPreference = "Stop"

Write-Host "=== OpenAudit Windows Service Uninstallation ==="

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Error "This script requires elevated Administrator privileges. Please run PowerShell as Administrator."
    exit 1
}

$existingService = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($existingService) {
    Write-Host "Stopping service $ServiceName..."
    Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 1
    Write-Host "Deleting service $ServiceName..."
    sc.exe delete $ServiceName | Out-Null
    Write-Host "[+] Service $ServiceName uninstalled successfully."
} else {
    Write-Host "Service $ServiceName is not installed."
}
