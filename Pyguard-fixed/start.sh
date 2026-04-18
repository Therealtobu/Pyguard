#!/data/data/com.termux/files/usr/bin/bash
# ─── Pyguard Bot – Termux Start Script ───────────────────────────────────────

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  🛡️  Pyguard Bot  –  Termux Launcher"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# Kiểm tra .env
if [ ! -f ".env" ]; then
    echo "❌  Chưa có file .env!"
    echo "    Chạy: cp .env.example .env && nano .env"
    exit 1
fi

# Kiểm tra obftool
if [ ! -d "obftool" ]; then
    echo "❌  Không tìm thấy thư mục obftool/"
    echo "    Hãy copy obftool vào thư mục này."
    exit 1
fi

# Cài dependencies nếu chưa có
if ! python -c "import discord" 2>/dev/null; then
    echo "📦 Cài dependencies..."
    pip install -r requirements.txt
fi

echo "🚀 Khởi động bot..."
python bot.py
