$ErrorActionPreference = "Stop"
$env:Path += ";D:\"
$repoRoot = Split-Path -Parent $PSScriptRoot
Set-Location $repoRoot

try {
  docker info --format '{{.ServerVersion}}' | Out-Null
  if ($LASTEXITCODE -ne 0) {
    throw "Docker engine is unavailable. Start Docker Desktop and try again."
  }
} catch {
  throw "Docker engine is unavailable. Start Docker Desktop and try again."
}

docker compose --profile local up -d db
if ($LASTEXITCODE -ne 0) {
  throw "Could not start the local PostgreSQL service."
}

$deadline = (Get-Date).AddSeconds(90)
$databaseReady = $false
while ((Get-Date) -lt $deadline) {
  $client = New-Object System.Net.Sockets.TcpClient
  try {
    $client.Connect("127.0.0.1", 5432)
    $databaseReady = $true
    break
  } catch {
    Start-Sleep -Seconds 2
  } finally {
    $client.Dispose()
  }
}
if (-not $databaseReady) {
  throw "PostgreSQL did not become available on 127.0.0.1:5432 within 90 seconds."
}

npm run db:migrate
if ($LASTEXITCODE -ne 0) {
  throw "Database migrations failed."
}
npm run seed
if ($LASTEXITCODE -ne 0) {
  throw "The re-runnable demo seed failed."
}

function Test-EndpointReady([string]$Uri) {
  try {
    $response = Invoke-WebRequest -UseBasicParsing -Uri $Uri -TimeoutSec 2
    return $response.StatusCode -eq 200
  } catch {
    return $false
  }
}

function Wait-ForEndpoint([string]$Uri, [string]$Name) {
  $deadline = (Get-Date).AddSeconds(60)
  while ((Get-Date) -lt $deadline) {
    if (Test-EndpointReady $Uri) {
      return
    }
    Start-Sleep -Seconds 1
  }
  throw "$Name did not become available at $Uri within 60 seconds."
}

$apiUrl = "http://127.0.0.1:3000"
$uiUrl = "http://127.0.0.1:5173"
if (-not (Test-EndpointReady "$apiUrl/healthz")) {
  $apiCommand = "Set-Location '$repoRoot'; `$env:Path += ';D:\'; npx tsx watch src/server/main.ts"
  Start-Process -FilePath "powershell.exe" -WorkingDirectory $repoRoot `
    -ArgumentList @("-NoProfile", "-NoExit", "-Command", $apiCommand) | Out-Null
}
if (-not (Test-EndpointReady $uiUrl)) {
  $webCommand = "Set-Location '$repoRoot'; `$env:Path += ';D:\'; npm run dev:web"
  Start-Process -FilePath "powershell.exe" -WorkingDirectory $repoRoot `
    -ArgumentList @("-NoProfile", "-NoExit", "-Command", $webCommand) | Out-Null
}

Wait-ForEndpoint "$apiUrl/healthz" "TrustVault API"
Wait-ForEndpoint $uiUrl "TrustVault UI"

Write-Output ""
Write-Output "TrustVault is ready."
Write-Output "API: $apiUrl"
Write-Output "UI:  $uiUrl"
Write-Output "Demo password: TrustVault-Local-Demo-2026!"
Write-Output "Demo accounts:"
Write-Output "  admin@trustvault.local"
Write-Output "  owner.one@trustvault.local"
Write-Output "  owner.two@trustvault.local"
Write-Output "  viewer.one@trustvault.local"
Write-Output "  viewer.two@trustvault.local"
Write-Output "  viewer.three@trustvault.local"
