# OpenAudit Agent Windows Service Installation Script
# Run with elevated Administrator privileges

param (
    [string]$InstallDir = "C:\Program Files\OpenAudit",
    [string]$ServiceName = "OpenAuditAgent"
)

$ErrorActionPreference = "Stop"

Write-Host "=== OpenAudit Windows Service Installation ==="

# Check administrator privilege
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Error "This script requires elevated Administrator privileges. Please run PowerShell as Administrator."
    exit 1
}

$agentExe = Join-Path $InstallDir "openaudit-agent.exe"
if (-not (Test-Path $agentExe)) {
    Write-Error "OpenAudit Agent binary not found at $agentExe. Please install the package files first."
    exit 1
}

# Stop and remove existing service if present
$existingService = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($existingService) {
    Write-Host "Stopping existing service $ServiceName..."
    Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
    sc.exe delete $ServiceName | Out-Null
    Start-Sleep -Seconds 2
}

# Create new Windows service
Write-Host "Creating Windows Service '$ServiceName'..."
sc.exe create $ServiceName binPath= "`"$agentExe`"" start= auto DisplayName= "OpenAudit Host Agent"
sc.exe description $ServiceName "OpenAudit host posture audit and node attestation daemon."

# Configure recovery options
sc.exe failure $ServiceName reset= 86400 actions= restart/60000/restart/60000//

Write-Host "Starting $ServiceName service..."
Start-Service -Name $ServiceName

Write-Host "[+] OpenAudit Agent successfully installed and started."
