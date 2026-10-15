<#
.SYNOPSIS
  Discover a running Kali VMware NAT guest and print VulnFusion variables.

This script only reads the VMX/DHCP lease and checks TCP/22. It never starts
the VM and never runs a security scanner.
#>
[CmdletBinding()]
param(
  [Parameter(Mandatory = $true)]
  [string]$VmxPath,
  [string]$LeasePath = 'C:\ProgramData\VMware\vmnetdhcp.leases',
  [string]$User = 'kali',
  [int]$Port = 22,
  [string]$KeyPath = ''
)

$ErrorActionPreference = 'Stop'
if (-not (Test-Path -LiteralPath $VmxPath)) { throw "VMX not found: $VmxPath" }
if (-not (Test-Path -LiteralPath $LeasePath)) { throw "VMware lease file not found: $LeasePath" }

$vmx = Get-Content -LiteralPath $VmxPath -Raw
$macMatch = [regex]::Match($vmx, '(?im)^ethernet\d+\.generatedAddress\s*=\s*"([0-9A-F:-]+)"')
if (-not $macMatch.Success) { throw 'No generated VMware MAC address found in VMX' }
$mac = ($macMatch.Groups[1].Value -replace ':','-').ToLowerInvariant()

$leaseText = Get-Content -LiteralPath $LeasePath -Raw
$blocks = [regex]::Matches($leaseText, '(?ms)lease\s+(?<ip>\d{1,3}(?:\.\d{1,3}){3})\s*\{(?<body>.*?)\}')
$ip = $null
foreach ($block in $blocks) {
  $body = $block.Groups['body'].Value
  if ($body -match '(?im)hardware\s+ethernet\s+(?<leaseMac>[0-9A-F:-]+)' -and (($Matches['leaseMac'] -replace ':','-').ToLowerInvariant() -eq $mac)) {
    $ip = $block.Groups['ip'].Value
    break
  }
}
if (-not $ip) {
  throw "No DHCP lease found for VMware MAC $mac. Start Kali and wait for DHCP, then retry."
}

$client = New-Object System.Net.Sockets.TcpClient
$async = $client.BeginConnect($ip, $Port, $null, $null)
$tcp = $async.AsyncWaitHandle.WaitOne(1500)
if ($tcp) {
  try { $client.EndConnect($async) } catch { $tcp = $false }
}
$client.Close()
Write-Output "# Kali VM: $VmxPath"
Write-Output "# VMware MAC: $mac"
Write-Output "# SSH reachable: $tcp"
Write-Output "VULNFUSION_KALI_HOST=$ip"
Write-Output "VULNFUSION_KALI_USER=$User"
Write-Output "VULNFUSION_KALI_PORT=$Port"
Write-Output "VULNFUSION_KALI_KEY=$KeyPath"
Write-Output 'VULNFUSION_KALI_REMOTE_ROOT=/opt/vulnfusion/workspaces'
Write-Output 'VULNFUSION_KALI_TIMEOUT=15'
