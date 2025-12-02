# PowerShell build script for Windows

Write-Host "🔨 Building IceNet EDR..." -ForegroundColor Cyan

# Build Rust agent
Write-Host "📦 Building agent..." -ForegroundColor Yellow
Set-Location agent
cargo build --release
Set-Location ..

# Build Go server
Write-Host "📦 Building server..." -ForegroundColor Yellow
Set-Location server
go build -o icenet-server.exe
Set-Location ..

Write-Host "✅ Build complete!" -ForegroundColor Green
Write-Host ""
Write-Host "Agent binary: agent\target\release\icenet-agent.exe"
Write-Host "Server binary: server\icenet-server.exe"
