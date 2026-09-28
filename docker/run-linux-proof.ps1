# Host runner (Windows): build the Linux proof image and run the in-container proof.
# Exits 2 when the Docker daemon is down (honest blocked, never a fake pass).
# NOTE: no `Stop` preference — every native call is followed by an explicit
# $LASTEXITCODE check, so a failing `docker info` must fall through to exit 2.
$Image = "bravoguard-linux-test"
$Log = Join-Path $PSScriptRoot "proof-linux-host.log"

docker info 2>&1 | Out-Null
if ($LASTEXITCODE -ne 0) {
  Write-Host "Docker daemon is DOWN (no Linux engine). Start it, wait until 'docker info' shows a Server, then re-run:"
  Write-Host "  Start-Process `"$Env:ProgramFiles\Docker\Docker\Docker Desktop.exe`""
  Write-Host "  docker info   # retry until Server section appears"
  Write-Host "  powershell -File docker/run-linux-proof.ps1"
  exit 2
}

docker build -f docker/Dockerfile.linux-test -t $Image .
if ($LASTEXITCODE -ne 0) { Write-Host "docker build FAILED"; exit 1 }

docker run --rm $Image | Tee-Object -FilePath $Log
$code = $LASTEXITCODE
Write-Host "proof container exit=$code (host log=$Log, container log=/tmp/proof.log)"
exit $code
