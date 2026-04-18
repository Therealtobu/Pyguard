# 🛡️ Pyguard Bot

Discord bot để obfuscate Python code bằng **ObfTool Stage 0→7**.

---

## 📁 Cấu trúc thư mục

```
pyguard/
├── bot.py              ← Bot chính
├── requirements.txt
├── .env.example
├── start.sh            ← Script chạy trên Termux
└── obftool/            ← Copy thư mục obftool vào đây
    ├── pipeline.py
    ├── stage0/
    ├── stage1/
    ├── ...
    └── stage7/
```

---

## 🚀 Cài đặt & Chạy

### Termux (Android)

```bash
# 1. Clone / copy thư mục pyguard về Termux
cd ~/pyguard

# 2. Tạo file .env
cp .env.example .env
nano .env   # Điền DISCORD_TOKEN

# 3. Copy obftool vào đây
cp -r /path/to/obftool ./obftool

# 4. Cài dependencies
pip install -r requirements.txt

# 5. Chạy
bash start.sh
# hoặc
python bot.py
```

---

## 🎮 Sử dụng

| Command | Mô tả |
|---------|-------|
| `/obf` | Mở menu chọn paste code hoặc upload file |
| `/help` | Xem hướng dẫn đầy đủ |
| `pg!obf` | Prefix version của `/obf` |
| `pg!obfcode <code>` | Paste code trực tiếp (hỗ trợ ` ```py ``` `) |

### Luồng sử dụng:

**Option 1 – Paste Code**
1. Gõ `/obf`
2. Nhấn nút **📋 Paste Code**
3. Modal hiện ra → dán code vào → Submit
4. Bot trả về file `obfuscated_final.py`

**Option 2 – Upload File**
1. Gõ `/obf`
2. Nhấn nút **📁 Upload File**
3. Bot yêu cầu reply tin nhắn đó với file `.py` đính kèm
4. Bot trả về file `<tên>_obfuscated.py`

---

## ⚙️ Pipeline Stages

| Stage | Mô tả |
|-------|-------|
| 0 | AST Parse, CFG Builder, Data Dependency Analysis |
| 1 | AST Obfuscation, TAC IR, IR Duplication & Mutation |
| 2 | SR-VM Bytecode Compilation + Encryption |
| 3 | GT-VM DAG + Fake Timeline Injection |
| 4 | LLVM IR + Native Compilation |
| 5 | Watchdog C Extension |
| 6 | Fragment Pool + Execution Graph |
| 7 | Pack → Compress → C Ext → Stub → Final Obfuscate |

---

## 🔒 Bảo vệ output

- **Anti-Trace** – timing, frame poison, code hash, thread hook
- **Anti-Replay** – polymorphic canary, silent self-destruct
- **Anti-Debug** – stack depth, module blacklist, SIGTRAP
- **Anti-Dump** – secret split + mprotect + decoy flood
- **Watermark** – `Protected by Pyguard V1`

---

## 🌐 Setup Discord Bot

1. Vào [Discord Developer Portal](https://discord.com/developers/applications)
2. Tạo New Application → Bot
3. Bật **Message Content Intent** trong Bot settings
4. Copy token → điền vào `.env`
5. Invite bot với scope: `bot`, `applications.commands`
6. Permission: `Send Messages`, `Attach Files`, `Read Message History`
