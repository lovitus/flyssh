# Cross-compile flyssh for all platforms
$ErrorActionPreference = "Stop"
$version = "1.0.0"
$outDir = "dist"
$ldflags = "-s -w -X main.Version=$version"

if (Test-Path $outDir) { Remove-Item -Recurse -Force $outDir }
New-Item -ItemType Directory -Path $outDir | Out-Null

$targets = @(
    @{ GOOS="windows"; GOARCH="amd64"; ext=".exe" },
    @{ GOOS="windows"; GOARCH="arm64"; ext=".exe" },
    @{ GOOS="linux";   GOARCH="amd64"; ext="" },
    @{ GOOS="linux";   GOARCH="arm64"; ext="" },
    @{ GOOS="darwin";  GOARCH="amd64"; ext="" },
    @{ GOOS="darwin";  GOARCH="arm64"; ext="" }
)

foreach ($t in $targets) {
    $name = "flyssh-$($t.GOOS)-$($t.GOARCH)$($t.ext)"
    $outPath = Join-Path $outDir $name
    Write-Host "Building $name ..." -ForegroundColor Cyan

    $env:GOOS   = $t.GOOS
    $env:GOARCH = $t.GOARCH
    $env:CGO_ENABLED = "0"

    go build -ldflags $ldflags -o $outPath .
    if ($LASTEXITCODE -ne 0) {
        Write-Host "FAILED: $name" -ForegroundColor Red
        exit 1
    }
    $size = (Get-Item $outPath).Length / 1MB
    Write-Host ("  -> {0:N2} MB" -f $size) -ForegroundColor Green
}

# Reset env
Remove-Item Env:\GOOS -ErrorAction SilentlyContinue
Remove-Item Env:\GOARCH -ErrorAction SilentlyContinue
Remove-Item Env:\CGO_ENABLED -ErrorAction SilentlyContinue

Write-Host "`nAll builds complete! Binaries in ./$outDir/" -ForegroundColor Green
Get-ChildItem $outDir | Format-Table Name, @{N="Size(MB)";E={"{0:N2}" -f ($_.Length/1MB)}} -AutoSize
