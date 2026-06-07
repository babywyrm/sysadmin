# Windows Container Builder using Crane (PowerShell)
# Usage: .\Build-WindowsContainer.ps1 -AppPath ".\myapp" -ImageName "myapp"

param(
    [Parameter(Mandatory=$true)]
    [string]$AppPath,
    
    [Parameter(Mandatory=$true)]
    [string]$ImageName,
    
    [string]$BaseImage = "mcr.microsoft.com/dotnet/aspnet:8.0-windowsservercore-ltsc2022",
    [string]$Tag = "latest",
    [string]$OutputTar = "",
    [switch]$Push,
    [string]$WorkDir = "",
    [string]$Cmd = "",
    [string]$Entrypoint = "",
    [string]$Platform = "windows/amd64",
    [string]$BuildConfig = "Release",
    [string]$Framework = "",
    [switch]$NoCleanup
)

function Write-ColorOutput {
    param(
        [string]$Message,
        [string]$Color = "White"
    )
    Write-Host $Message -ForegroundColor $Color
}

function Write-Info { Write-ColorOutput -Message "[INFO] $args" -Color "Cyan" }
function Write-Success { Write-ColorOutput -Message "[SUCCESS] $args" -Color "Green" }
function Write-Warning { Write-ColorOutput -Message "[WARNING] $args" -Color "Yellow" }
function Write-Error { Write-ColorOutput -Message "[ERROR] $args" -Color "Red" }

# Check if crane is installed
if (-not (Get-Command crane -ErrorAction SilentlyContinue)) {
    Write-Error "crane is not installed. Download from: https://github.com/google/go-containerregistry/releases"
    exit 1
}

# Validate paths
if (-not (Test-Path $AppPath)) {
    Write-Error "Application path does not exist: $AppPath"
    exit 1
}

$FullImageName = "${ImageName}:${Tag}"
$LayerTar = "layer.tar"

Write-Info "Starting Windows container build process..."
Write-Info "App Path: $AppPath"
Write-Info "Base Image: $BaseImage"
Write-Info "Output Image: $FullImageName"
Write-Info "Platform: $Platform"

try {
    # Step 1: Build the application
    Write-Info "Building application..."
    Push-Location $AppPath
    
    # Detect and build .NET project
    if (Get-ChildItem -Filter "*.csproj" -ErrorAction SilentlyContinue) {
        $BuildCmd = "dotnet publish -c $BuildConfig -o ./app"
        if ($Framework) {
            $BuildCmd += " -f $Framework"
        }
        
        Write-Info "Detected .NET project, running: $BuildCmd"
        Invoke-Expression $BuildCmd
        
        if (-not (Test-Path "./app")) {
            Write-Error "Build output directory './app' not found"
            exit 1
        }
        
        $AppDir = "./app"
    } else {
        Write-Warning "Unknown project type, using entire directory"
        $AppDir = "."
    }
    
    # Step 2: Create application layer
    Write-Info "Creating application layer..."
    tar -cf "../$LayerTar" -C $AppDir .
    
    Pop-Location
    
    # Step 3: Build the container image
    Write-Info "Assembling container image with crane..."
    
    $CraneCmd = "crane append --platform=$Platform -f $LayerTar -t $FullImageName -b $BaseImage"
    
    if ($OutputTar) {
        $CraneCmd += " -o $OutputTar"
        Write-Info "Saving image as: $OutputTar"
    } else {
        Write-Info "Building image: $FullImageName"
    }
    
    Invoke-Expression $CraneCmd
    
    if ($LASTEXITCODE -eq 0) {
        Write-Success "Image assembled successfully!"
    } else {
        Write-Error "Failed to assemble image"
        exit 1
    }
    
    # Step 4: Configure runtime settings
    if ($WorkDir -or $Cmd -or $Entrypoint) {
        Write-Info "Applying runtime configuration..."
        
        $MutateCmd = "crane mutate"
        
        if ($WorkDir) {
            $MutateCmd += " --workdir=$WorkDir"
            Write-Info "Setting working directory: $WorkDir"
        }
        
        if ($Cmd) {
            $MutateCmd += " --cmd=$Cmd"
            Write-Info "Setting command: $Cmd"
        }
        
        if ($Entrypoint) {
            $MutateCmd += " --entrypoint=$Entrypoint"
            Write-Info "Setting entrypoint: $Entrypoint"
        }
        
        $MutateCmd += " $FullImageName"
        Invoke-Expression $MutateCmd
    }
    
    # Step 5: Push to registry if requested
    if ($Push -and -not $OutputTar) {
        Write-Info "Image already pushed to registry during build"
    } elseif ($Push -and $OutputTar) {
        Write-Info "Pushing image to registry..."
        crane push $OutputTar $FullImageName
    }
    
    # Summary
    Write-Success "Windows container build completed!"
    Write-Host ""
    Write-Host "Summary:"
    Write-Host "  Source: $AppPath"
    Write-Host "  Base Image: $BaseImage"
    Write-Host "  Output Image: $FullImageName"
    Write-Host "  Platform: $Platform"
    
    if ($OutputTar) {
        Write-Host "  Saved as: $OutputTar"
        Write-Host ""
        Write-Host "To load into Docker:"
        Write-Host "  docker load -i $OutputTar"
    }
    
    if ($Push) {
        Write-Host "  Pushed to registry: Yes"
    }
    
    Write-Host ""
    Write-Host "To run the container:"
    Write-Host "  docker run --rm -it -p 8080:80 $FullImageName"
    
    Write-Success "Done!"
    
} finally {
    # Cleanup
    if (-not $NoCleanup) {
        Write-Info "Cleaning up temporary files..."
        Remove-Item $LayerTar -ErrorAction SilentlyContinue
    }
}
