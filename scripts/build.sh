#!/bin/bash
set -e

echo "🔨 Building IceNet EDR..."

# Build Rust agent
echo "📦 Building agent..."
cd agent
cargo build --release
cd ..

# Build Go server
echo "📦 Building server..."
cd server
go build -o icenet-server
cd ..

echo "✅ Build complete!"
echo ""
echo "Agent binary: agent/target/release/icenet-agent"
echo "Server binary: server/icenet-server"
