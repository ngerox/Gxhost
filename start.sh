#!/bin/bash
# ROCK AXEE Bot Hosting Panel - Start Script

# Always run from the project directory so relative paths and local assets
# remain stable when the process is restarted by a supervisor/host.
cd "$(dirname "$(realpath "$0")")"

echo "🚀 ASDCODEX Bot Hosting Panel"
echo "=============================="

# Check if virtual environment exists, create if not
if [ ! -d "venv" ]; then
    echo "📦 Creating virtual environment..."
    python3 -m venv venv
fi

# Activate virtual environment
echo "🔧 Activating virtual environment..."
source venv/bin/activate

# Install dependencies
echo "📥 Installing dependencies..."
pip install -q -r requirements.txt

# Set default environment variables
export PORT="${PORT:-5001}"
export SECRET_KEY="${SECRET_KEY:-senkucodex_secret_change_me}"
export DATA_DIR="${DATA_DIR:-./data}"

echo ""
echo "🌐 Starting server on port $PORT..."
echo "📍 URL: http://localhost:$PORT"
echo ""
echo "🔑 Default login:"
echo "   Username: ASDCODEX"
echo "   Password: ASD@ASAD"
echo ""

python app.py
