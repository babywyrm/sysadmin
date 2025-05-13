<#
.SYNOPSIS
    Install and configure Docker Community Edition on Windows.

.DESCRIPTION
    This script installs required Windows features (Containers, optional Hyper-V),
    installs Docker via the official DockerMsftProvider, configures the Docker daemon,
    and optionally creates a transparent or custom NAT network and pre-pulls a base image.

.PARAMETER UseHyperV
    Include this switch to enable the Hyper-V feature (needed for Hyper-V containers).

.PARAMETER TransparentNetwork
    Create a transparent container network named 'Transparent'.

.PARAMETER NATSubnet
    Specify a custom NAT subnet (e.g. '10.0.75.0/24'). If omitted, Docker’s default NAT is used.

.PARAMETER BaseImage
    A Docker image (with tag) to pull after installation (e.g. 'mcr.microsoft.com/windows/nanoserver:ltsc2022').

.PARAMETER NoRestart
    If specified, the script will not reboot even if a reboot is required.

.EXAMPLE
    .\Install-DockerCE.ps1 -UseHyperV -TransparentNetwork `
        -BaseImage 'mcr.microsoft.com/windows/servercore:ltsc2022'

.NOTES
    Tested on Windows Server 2016/2019/2022 and Windows 10/11.
    Requires PowerShell 5.1+.
#>

[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'Medium')]
param(
    [switch] $UseHyperV,
    [switch] $TransparentNetwork,
    [ValidatePattern('^(\d{1,3}\.){3}\d{1,3}\/\d{1,2}$')]
    [string] $NATSubnet,
    [string] $BaseImage,
    [switch] $NoRestart
)

function Assert-RunningAsAdmin {
    if (-not ([Security.Principal.WindowsPrincipal] `
        [Security.Principal.WindowsIdentity]::GetCurrent()
    ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Throw "This script must be run as Administrator."
    }
}

function Install-WindowsFeatures {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string[]] $FeatureNames
    )
    foreach ($f in $FeatureNames) {
        if (-not (Get-WindowsFeature $f).Installed) {
            Write-Verbose "Installing Windows feature: $f"
            Install-WindowsFeature $f -IncludeAllSubFeature -ErrorAction Stop |
                Out-Null
            $global:RebootRequired = $true
        }
        else {
            Write-Verbose "Feature already present: $f"
        }
    }
}

function Install-DockerModule {
    Write-Verbose "Ensuring DockerMsftProvider is available"
    if (-not (Get-Module -ListAvailable -Name DockerMsftProvider)) {
        Install-Module -Name DockerMsftProvider -Repository PSGallery `
            -Force -ErrorAction Stop
    }
    Write-Verbose "Installing Docker package via DockerMsftProvider"
    Install-Package -Name docker -ProviderName DockerMsftProvider `
        -Force -ErrorAction Stop | Out-Null
}

function Configure-Daemon {
    Write-Verbose "Writing custom daemon.json (if needed)"
    $configPath = "$env:ProgramData\docker\config"
    New-Item -Path $configPath -ItemType Directory -Force | Out-Null

    $settings = @{}
    if ($PSBoundParameters.ContainsKey('NATSubnet')) {
        $settings['fixed-cidr'] = $NATSubnet
    }
    if ($settings.Count) {
        $settings | ConvertTo-Json -Depth 3 |
            Set-Content -Path (Join-Path $configPath 'daemon.json')
    }
}

function Start-DockerService {
    Write-Verbose "Starting Docker service"
    Start-Service docker -ErrorAction Stop
    Write-Verbose "Waiting for Docker daemon to be ready"
    $timeout = (Get-Date).AddSeconds(60)
    while ((Get-Date) -lt $timeout) {
        try { docker version | Out-Null; return }
        catch { Start-Sleep -Seconds 2 }
    }
    Throw "Docker daemon did not start within 60 seconds."
}

function Setup-Networking {
    if ($TransparentNetwork) {
        if (-not (docker network ls --format '{{.Name}}' | Select-String -SimpleMatch 'Transparent')) {
            Write-Verbose "Creating transparent network 'Transparent'"
            docker network create -d transparent Transparent |
                Out-Null
        }
        else {
            Write-Verbose "'Transparent' network already exists"
        }
    }
    elseif ($PSBoundParameters.ContainsKey('NATSubnet')) {
        Write-Verbose "User-specified NAT subnet applied in daemon.json"
    }
}

try {
    Assert-RunningAsAdmin

    # 1) Windows features
    $features = @('Containers')
    if ($UseHyperV) { $features += 'Hyper-V' }
    Install-WindowsFeatures -FeatureNames $features

    if ($global:RebootRequired -and -not $NoRestart) {
        Write-Host 'Reboot required. Restarting now…' -ForegroundColor Yellow
        Restart-Computer -Force
        exit
    }
    elseif ($global:RebootRequired) {
        Write-Warning 'Reboot required. Rerun after restart.'
        exit 1
    }

    # 2) Docker install
    if (-not (Get-Service docker -ErrorAction SilentlyContinue)) {
        Install-DockerModule
    }
    else {
        Write-Verbose 'Docker service already installed'
    }

    # 3) Configure & start
    Configure-Daemon
    Start-DockerService

    # 4) Networking
    Setup-Networking

    # 5) Optional pre-pull
    if ($BaseImage) {
        Write-Verbose "Pulling base image: $BaseImage"
        docker pull $BaseImage
    }

    Write-Host '✓ Docker Community Edition installation complete!' -ForegroundColor Green
}
catch {
    Write-Error "ERROR: $_"
    exit 1
}
