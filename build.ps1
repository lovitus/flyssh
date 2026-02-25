# Cross-compile flyssh for all platforms
$ErrorActionPreference = "Stop"
$version = "1.0.1"
$outDir = "dist"
$ldflags = "-s -w -X main.Version=$version"

if (Test-Path $outDir) { Remove-Item -Recurse -Force $outDir }
New-Item -ItemType Directory -Path $outDir | Out-Null

# --- Build embedded relay binaries (for TCP forwarding fallback) ---
$relayDir = "pkg/forwarding/relaybin"
New-Item -ItemType Directory -Force -Path $relayDir | Out-Null
$relayTargets = @(
    @{ GOOS="linux";   GOARCH="amd64" },
    @{ GOOS="linux";   GOARCH="arm64" },
    @{ GOOS="linux";   GOARCH="386" },
    @{ GOOS="linux";   GOARCH="arm"; GOARM="6" },
    @{ GOOS="darwin";  GOARCH="amd64" },
    @{ GOOS="darwin";  GOARCH="arm64" },
    @{ GOOS="freebsd"; GOARCH="amd64" }
)
foreach ($rt in $relayTargets) {
    $rname = "relay-$($rt.GOOS)-$($rt.GOARCH)"
    $rpath = Join-Path $relayDir $rname
    Write-Host "Building relay: $rname ..." -ForegroundColor Yellow
    $env:GOOS = $rt.GOOS
    $env:GOARCH = $rt.GOARCH
    $env:CGO_ENABLED = "0"
    if ($rt.GOARM) { $env:GOARM = $rt.GOARM } else { Remove-Item Env:\GOARM -ErrorAction SilentlyContinue }
    go build -ldflags "-s -w" -trimpath -o $rpath ./cmd/relay
    if ($LASTEXITCODE -ne 0) {
        Write-Host "FAILED: relay $rname" -ForegroundColor Red
        exit 1
    }
    # Gzip the relay binary
    $raw = [System.IO.File]::ReadAllBytes($rpath)
    $ms = New-Object System.IO.MemoryStream
    $gz = New-Object System.IO.Compression.GZipStream($ms, [System.IO.Compression.CompressionLevel]::Optimal)
    $gz.Write($raw, 0, $raw.Length)
    $gz.Close()
    [System.IO.File]::WriteAllBytes("$rpath.gz", $ms.ToArray())
    $ms.Close()
    $origKB = [math]::Round($raw.Length / 1KB)
    $gzKB = [math]::Round((Get-Item "$rpath.gz").Length / 1KB)
    Write-Host "  -> ${origKB}KB -> ${gzKB}KB (gzipped)" -ForegroundColor Green
}
Write-Host ""

# --- Build main flyssh binaries ---
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
