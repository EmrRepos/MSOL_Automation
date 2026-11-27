param(
    [string]$OutputDirectory = "release"
)

$ErrorActionPreference = "Stop"
$root = $PSScriptRoot
$python = Join-Path $root ".venv\Scripts\python.exe"
if (-not (Test-Path -LiteralPath $python -PathType Leaf)) {
    throw "Shared environment not found. Run py -3.14 setup_environment.py first."
}

$output = if ([System.IO.Path]::IsPathRooted($OutputDirectory)) {
    [System.IO.Path]::GetFullPath($OutputDirectory)
} else {
    [System.IO.Path]::GetFullPath((Join-Path $root $OutputDirectory))
}
if (Test-Path -LiteralPath $output) {
    throw "Output directory already exists: $output. Choose a new -OutputDirectory; existing files will not be overwritten."
}

$version = & $python -B -m PyInstaller --version
if ($LASTEXITCODE -ne 0) {
    throw "PyInstaller is unavailable. Run .\.venv\Scripts\python.exe -m pip install -r requirements-build.txt."
}
if ($version -ne "6.22.3") {
    throw "Expected PyInstaller 6.22.3, found $version. Install requirements-build.txt before building."
}

New-Item -ItemType Directory -Path $output | Out-Null
$work = Join-Path $output "_build"
$spec = Join-Path $output "_spec"
$usb = Join-Path $root "plugins\usb"
$ethernet = Join-Path $root "plugins\ethernetip"
$profiles = Join-Path $usb "device_profiles"

$previousBytecodeSetting = $env:PYTHONDONTWRITEBYTECODE
try {
    $env:PYTHONDONTWRITEBYTECODE = "1"
    & $python -B -m PyInstaller --onefile --windowed --name USB `
        --paths $usb --exclude-module PyQt5 --collect-all libusb_package `
        --add-data "${profiles}:device_profiles" `
        --distpath $output --workpath $work --specpath $spec `
        (Join-Path $root "release_tools\usb_entry.py")
    if ($LASTEXITCODE -ne 0) {
        throw "USB build failed. Inspect the output above; do not distribute this build."
    }

    & $python -B -m PyInstaller --onefile --windowed --name Ethernetip `
        --paths $ethernet --distpath $output --workpath $work --specpath $spec `
        (Join-Path $ethernet "main.py")
    if ($LASTEXITCODE -ne 0) {
        throw "EtherNet/IP build failed. Inspect the output above; do not distribute this build."
    }
    & $python -B (Join-Path $root "release_tools\verify_archives.py") $output
    if ($LASTEXITCODE -ne 0) {
        throw "Bundle verification failed. Do not distribute this build."
    }
} finally {
    $env:PYTHONDONTWRITEBYTECODE = $previousBytecodeSetting
}

Write-Host "Built $output\USB.exe and $output\Ethernetip.exe"
Write-Host "Verify both executables before sharing; _build and _spec are not release files."
