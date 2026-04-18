"""
╔══════════════════════════════════════════════╗
║         PYGUARD  –  Obfuscation Bot          ║
║   Stage 0-7 Pipeline  |  discord.py v2       ║
╚══════════════════════════════════════════════╝
"""
from __future__ import annotations

import asyncio
import io
import os
import random
import shutil
import sys
import tempfile
import time
import traceback
from pathlib import Path

import discord
from discord import app_commands
from discord.ext import commands
from dotenv import load_dotenv

load_dotenv()

# ─── Config ───────────────────────────────────────────────────────────────────

TOKEN        = os.getenv("DISCORD_TOKEN", "")
OBFTOOL_DIR  = Path(__file__).parent / "obftool"
MAX_FILE_MB  = 2
MAX_CODE_LEN = 50_000   # chars for modal paste

# ─── Colours & assets ─────────────────────────────────────────────────────────

C_BRAND   = 0x5865F2   # blurple
C_SUCCESS = 0x57F287   # green
C_ERROR   = 0xED4245   # red
C_WARN    = 0xFEE75C   # yellow
C_PROC    = 0x5865F2   # processing

SHIELD = "🛡️"
LOCK   = "🔒"
GEAR   = "⚙️"
CHECK  = "✅"
CROSS  = "❌"
FILE_  = "📁"
PASTE  = "📋"
CLOCK  = "⏱️"

# ─── Intents ──────────────────────────────────────────────────────────────────

intents = discord.Intents.default()
intents.message_content = True
intents.guilds           = True

bot = commands.Bot(command_prefix="pg!", intents=intents)

# ══════════════════════════════════════════════════════════════════════════════
# Pipeline runner (async subprocess)
# ══════════════════════════════════════════════════════════════════════════════

async def run_pipeline(source_code: str, seed: int = 0) -> dict:
    """
    Runs the ObfTool pipeline in a temp directory.
    Returns dict with keys: success, output_path, log, elapsed, stats.
    """
    work_dir = Path(tempfile.mkdtemp(prefix="pyguard_"))
    src_file  = work_dir / "input.py"
    out_dir   = work_dir / "build"
    out_dir.mkdir()

    try:
        src_file.write_text(source_code, encoding="utf-8")

        cmd = [
            sys.executable, "-m", "pipeline",
            str(src_file),
            "--seed", str(seed),
            "--out",  str(out_dir),
        ]

        t0 = time.perf_counter()
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            cwd=str(OBFTOOL_DIR),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
            env={**os.environ, "PYTHONPATH": str(OBFTOOL_DIR)},
        )

        try:
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=120)
        except asyncio.TimeoutError:
            proc.kill()
            return {"success": False, "log": "⏰ Pipeline timed out (>120s).", "elapsed": 120}

        elapsed = time.perf_counter() - t0
        log     = stdout.decode("utf-8", errors="replace")

        if proc.returncode != 0:
            return {"success": False, "log": log[-3000:], "elapsed": elapsed}

        final_py = out_dir / "obfuscated_final.py"
        if not final_py.exists():
            return {"success": False, "log": "Output file not found.\n" + log[-2000:], "elapsed": elapsed}

        # Collect stats from log
        stats = _parse_stats(log)

        return {
            "success":     True,
            "output_path": final_py,
            "work_dir":    work_dir,
            "log":         log,
            "elapsed":     elapsed,
            "stats":       stats,
        }

    except Exception:
        shutil.rmtree(work_dir, ignore_errors=True)
        return {"success": False, "log": traceback.format_exc(), "elapsed": 0}


def _parse_stats(log: str) -> dict:
    """Extract key numbers from pipeline log."""
    stats: dict = {}
    for line in log.splitlines():
        line = line.strip()
        if "Hot functions"       in line: stats["hot_fns"]     = _last_int(line)
        if "SR-VM functions"     in line: stats["srvm_fns"]    = _last_int(line)
        if "GT-VM DAGs"          in line: stats["gtvm_dags"]   = _last_int(line)
        if "Native blocks"       in line: stats["native_blks"] = _last_int(line)
        if "Graph nodes / edges" in line:
            parts = line.split()[-1].split("/")
            try: stats["nodes"], stats["edges"] = int(parts[0]), int(parts[1])
            except: pass
        if "Fragments real/junk" in line:
            parts = line.split()[-1].split("/")
            try: stats["real"], stats["junk"] = int(parts[0]), int(parts[1])
            except: pass
        if "Total payload"       in line: stats["payload_bytes"] = _last_int(line.replace(",",""))
        if "Build time"          in line:
            try: stats["build_time"] = float(line.split()[-1].replace("s",""))
            except: pass
    return stats


def _last_int(s: str) -> int | None:
    parts = s.replace(",","").split()
    for p in reversed(parts):
        try: return int(p)
        except: pass
    return None

# ══════════════════════════════════════════════════════════════════════════════
# Shared helpers
# ══════════════════════════════════════════════════════════════════════════════

def _processing_embed(title: str = "Obfuscating…") -> discord.Embed:
    e = discord.Embed(
        title       = f"{GEAR} {title}",
        description = "Pipeline đang chạy, vui lòng đợi…\n"
                      "```\nStage 0 → AST Parse & CFG\nStage 1 → IR Generation\n"
                      "Stage 2 → SR-VM Bytecode\nStage 3 → GT-VM DAG\n"
                      "Stage 4 → Native LLVM\nStage 5 → Watchdog\n"
                      "Stage 6 → Fragment & Graph\nStage 7 → Pack & Stub\n```",
        colour      = C_PROC,
    )
    e.set_footer(text="Pyguard  •  Protected by ObfTool Stage 0-7")
    return e


def _success_embed(res: dict, filename: str) -> discord.Embed:
    stats = res.get("stats", {})
    e = discord.Embed(
        title   = f"{SHIELD} Obfuscation hoàn thành!",
        colour  = C_SUCCESS,
    )
    e.add_field(name=f"{LOCK} Output", value=f"`{filename}`", inline=False)

    # Stats block
    lines = []
    if stats.get("srvm_fns")    is not None: lines.append(f"SR-VM functions  : **{stats['srvm_fns']}**")
    if stats.get("gtvm_dags")   is not None: lines.append(f"GT-VM DAGs       : **{stats['gtvm_dags']}**")
    if stats.get("native_blks") is not None: lines.append(f"Native blocks    : **{stats['native_blks']}**")
    if stats.get("nodes")       is not None: lines.append(f"Graph nodes/edges: **{stats['nodes']}/{stats.get('edges',0)}**")
    if stats.get("real")        is not None: lines.append(f"Fragments r/junk : **{stats['real']}/{stats.get('junk',0)}**")
    if stats.get("payload_bytes") is not None:
        lines.append(f"Total payload    : **{stats['payload_bytes']:,}** bytes")

    if lines:
        e.add_field(name=f"{GEAR} Build Stats", value="\n".join(lines), inline=False)

    elapsed = res.get("elapsed", 0)
    e.add_field(name=f"{CLOCK} Time", value=f"`{elapsed:.2f}s`", inline=True)
    e.set_footer(text='Watermark: "Protected by Pyguard V1"  •  Anti-debug / Anti-trace / Anti-dump active')
    return e


def _error_embed(msg: str, log: str = "") -> discord.Embed:
    e = discord.Embed(
        title   = f"{CROSS} Obfuscation thất bại",
        colour  = C_ERROR,
    )
    e.add_field(name="Lỗi", value=f"```\n{msg[:500]}\n```", inline=False)
    if log:
        snippet = log[-800:]
        e.add_field(name="Log (cuối)", value=f"```\n{snippet}\n```", inline=False)
    e.set_footer(text="Pyguard  •  Kiểm tra lại code input")
    return e

# ══════════════════════════════════════════════════════════════════════════════
# Modal – Paste Code
# ══════════════════════════════════════════════════════════════════════════════

class PasteModal(discord.ui.Modal, title="📋 Paste Python Code"):
    code = discord.ui.TextInput(
        label       = "Python source code",
        style       = discord.TextStyle.paragraph,
        placeholder = "Dán code Python của bạn vào đây…",
        required    = True,
        max_length  = 4000,
    )

    async def on_submit(self, interaction: discord.Interaction):
        await interaction.response.defer(thinking=True, ephemeral=False)
        source = self.code.value.strip()

        if not source:
            await interaction.followup.send(
                embed=_error_embed("Code không được để trống."), ephemeral=True)
            return

        if len(source) > MAX_CODE_LEN:
            await interaction.followup.send(
                embed=_error_embed(f"Code quá dài ({len(source):,} ký tự). Giới hạn: {MAX_CODE_LEN:,}."),
                ephemeral=True)
            return

        # Show processing embed
        proc_msg = await interaction.followup.send(embed=_processing_embed())

        seed = random.randint(0, 0xFFFF_FFFF)
        res  = await run_pipeline(source, seed=seed)

        if not res["success"]:
            await proc_msg.edit(
                embed=_error_embed("Pipeline lỗi.", res.get("log", "")))
            return

        out_path: Path = res["output_path"]
        file_bytes = out_path.read_bytes()
        fname      = "obfuscated_final.py"
        disc_file  = discord.File(io.BytesIO(file_bytes), filename=fname)

        await proc_msg.edit(embed=_success_embed(res, fname), attachments=[disc_file])
        shutil.rmtree(res["work_dir"], ignore_errors=True)

# ══════════════════════════════════════════════════════════════════════════════
# View – Choose input method
# ══════════════════════════════════════════════════════════════════════════════

class ChooseView(discord.ui.View):
    def __init__(self, timeout: float = 120):
        super().__init__(timeout=timeout)
        self._file_waiting: dict[int, bool] = {}   # channel_id → waiting

    @discord.ui.button(label="Paste Code", emoji=PASTE, style=discord.ButtonStyle.primary)
    async def paste_btn(self, interaction: discord.Interaction, _: discord.ui.Button):
        await interaction.response.send_modal(PasteModal())

    @discord.ui.button(label="Upload File", emoji=FILE_, style=discord.ButtonStyle.secondary)
    async def file_btn(self, interaction: discord.Interaction, _: discord.ui.Button):
        await interaction.response.send_message(
            embed=discord.Embed(
                title       = f"{FILE_} Upload file Python",
                description = f"Hãy **reply tin nhắn này** và đính kèm file `.py` cần obfuscate.\n"
                              f"Giới hạn: **{MAX_FILE_MB} MB**  |  Hết hạn: **60 giây**",
                colour      = C_BRAND,
            ),
            ephemeral=False,
        )

        prompt_msg = await interaction.original_response()
        channel    = interaction.channel
        author     = interaction.user

        def check(m: discord.Message) -> bool:
            return (
                m.author.id == author.id
                and m.channel.id == channel.id
                and m.reference is not None
                and m.reference.message_id == prompt_msg.id
                and len(m.attachments) > 0
            )

        try:
            msg: discord.Message = await bot.wait_for("message", check=check, timeout=60)
        except asyncio.TimeoutError:
            await prompt_msg.edit(
                embed=discord.Embed(
                    title="⏰ Hết giờ",
                    description="Không nhận được file trong 60 giây.",
                    colour=C_WARN,
                )
            )
            return

        att = msg.attachments[0]

        if not att.filename.endswith(".py"):
            await channel.send(
                embed=_error_embed(f"File `{att.filename}` không phải `.py`."),
                reference=msg,
            )
            return

        if att.size > MAX_FILE_MB * 1024 * 1024:
            await channel.send(
                embed=_error_embed(f"File quá lớn ({att.size/1024/1024:.1f} MB). Giới hạn {MAX_FILE_MB} MB."),
                reference=msg,
            )
            return

        proc_msg = await channel.send(embed=_processing_embed(f"Obfuscating `{att.filename}`…"), reference=msg)

        try:
            raw = await att.read()
            source = raw.decode("utf-8")
        except Exception as ex:
            await proc_msg.edit(embed=_error_embed(f"Không đọc được file: {ex}"))
            return

        seed = random.randint(0, 0xFFFF_FFFF)
        res  = await run_pipeline(source, seed=seed)

        if not res["success"]:
            await proc_msg.edit(embed=_error_embed("Pipeline lỗi.", res.get("log", "")))
            return

        out_path: Path = res["output_path"]
        base    = Path(att.filename).stem
        fname   = f"{base}_obfuscated.py"
        disc_file = discord.File(io.BytesIO(out_path.read_bytes()), filename=fname)

        await proc_msg.edit(embed=_success_embed(res, fname), attachments=[disc_file])
        shutil.rmtree(res["work_dir"], ignore_errors=True)

    async def on_timeout(self):
        for child in self.children:
            child.disabled = True  # type: ignore

# ══════════════════════════════════════════════════════════════════════════════
# Slash command
# ══════════════════════════════════════════════════════════════════════════════

@bot.tree.command(name="obf", description="🛡️ Obfuscate Python code bằng Pyguard (Stage 0-7)")
async def obf_slash(interaction: discord.Interaction):
    embed = discord.Embed(
        title       = f"{SHIELD} Pyguard Obfuscator",
        description = (
            "Chọn cách nhập code Python của bạn:\n\n"
            f"{PASTE} **Paste Code** — dán thẳng code vào modal\n"
            f"{FILE_} **Upload File** — đính kèm file `.py`"
        ),
        colour=C_BRAND,
    )
    embed.set_footer(text="Pyguard  •  ObfTool Stage 0→7  •  Protected by Pyguard V1")
    await interaction.response.send_message(embed=embed, view=ChooseView())


# ── Prefix fallback: pg!obf ────────────────────────────────────────────────────

@bot.command(name="obf", aliases=["obfuscate"])
async def obf_prefix(ctx: commands.Context):
    """pg!obf – Mở menu obfuscate."""
    embed = discord.Embed(
        title       = f"{SHIELD} Pyguard Obfuscator",
        description = (
            "Chọn cách nhập code Python của bạn:\n\n"
            f"{PASTE} **Paste Code** — dán thẳng code vào modal\n"
            f"{FILE_} **Upload File** — đính kèm file `.py`"
        ),
        colour=C_BRAND,
    )
    embed.set_footer(text="Pyguard  •  ObfTool Stage 0→7  •  Protected by Pyguard V1")
    await ctx.send(embed=embed, view=ChooseView())


# ── Quick prefix: pg!obf (inline code block) ──────────────────────────────────

@bot.command(name="obfcode")
async def obf_inline(ctx: commands.Context, *, code: str):
    """pg!obfcode <code> – Obfuscate code dán thẳng (không cần modal)."""
    # Strip markdown code fences
    src = code.strip()
    if src.startswith("```python"): src = src[9:]
    elif src.startswith("```py"):   src = src[5:]
    elif src.startswith("```"):     src = src[3:]
    if src.endswith("```"):         src = src[:-3]
    src = src.strip()

    if not src:
        await ctx.send(embed=_error_embed("Code rỗng."))
        return

    proc_msg = await ctx.send(embed=_processing_embed())
    seed = random.randint(0, 0xFFFF_FFFF)
    res  = await run_pipeline(src, seed=seed)

    if not res["success"]:
        await proc_msg.edit(embed=_error_embed("Pipeline lỗi.", res.get("log", "")))
        return

    out_path: Path = res["output_path"]
    fname     = "obfuscated_final.py"
    disc_file = discord.File(io.BytesIO(out_path.read_bytes()), filename=fname)

    await proc_msg.edit(embed=_success_embed(res, fname))
    await ctx.send(file=disc_file)
    shutil.rmtree(res["work_dir"], ignore_errors=True)

# ══════════════════════════════════════════════════════════════════════════════
# Help command
# ══════════════════════════════════════════════════════════════════════════════

@bot.tree.command(name="help", description="📖 Hướng dẫn sử dụng Pyguard")
async def help_slash(interaction: discord.Interaction):
    e = discord.Embed(
        title   = f"{SHIELD} Pyguard – Hướng dẫn",
        colour  = C_BRAND,
    )
    e.add_field(
        name  = "Slash Commands",
        value = (
            "`/obf` — Mở menu chọn nhập code (paste hoặc upload)\n"
            "`/help` — Hiển thị trang này"
        ),
        inline=False,
    )
    e.add_field(
        name  = "Prefix Commands (`pg!`)",
        value = (
            "`pg!obf` — Mở menu chọn nhập code\n"
            "`pg!obfcode <code>` — Paste code trực tiếp (hỗ trợ code block)\n"
        ),
        inline=False,
    )
    e.add_field(
        name  = f"{GEAR} Pipeline Stages",
        value = (
            "**Stage 0** – AST Parse, CFG, Data Dependency\n"
            "**Stage 1** – AST Obfuscation, TAC IR, IR Mutation\n"
            "**Stage 2** – SR-VM Bytecode + Encryption\n"
            "**Stage 3** – GT-VM DAG + Fake Timelines\n"
            "**Stage 4** – LLVM Native Compilation\n"
            "**Stage 5** – Watchdog C Extension\n"
            "**Stage 6** – Fragment + Execution Graph\n"
            "**Stage 7** – Pack, Stub, Final Obfuscation"
        ),
        inline=False,
    )
    e.add_field(
        name  = f"{LOCK} Bảo vệ bao gồm",
        value = (
            "Anti-Trace • Anti-Replay • Anti-Debug • Anti-Dump\n"
            "XOR String Encrypt • Control Flow Flatten\n"
            "Watermark: `Protected by Pyguard V1`"
        ),
        inline=False,
    )
    e.add_field(name="Giới hạn", value=f"File: **{MAX_FILE_MB} MB**  |  Paste: **{MAX_CODE_LEN:,}** ký tự  |  Timeout: **120s**", inline=False)
    e.set_footer(text="Pyguard  •  ObfTool Stage 0→7")
    await interaction.response.send_message(embed=e, ephemeral=True)

# ══════════════════════════════════════════════════════════════════════════════
# Events
# ══════════════════════════════════════════════════════════════════════════════

@bot.event
async def on_ready():
    print(f"\n{'─'*45}")
    print(f"  {SHIELD}  Pyguard Bot  –  online")
    print(f"  Logged in as: {bot.user} ({bot.user.id})")
    print(f"  Guilds: {len(bot.guilds)}")
    print(f"  ObfTool: {OBFTOOL_DIR}")
    print(f"{'─'*45}\n")
    await bot.tree.sync()
    await bot.change_presence(
        activity=discord.Activity(
            type=discord.ActivityType.watching,
            name="🛡️ /obf to protect your code"
        )
    )


@bot.event
async def on_command_error(ctx: commands.Context, error):
    if isinstance(error, commands.CommandNotFound):
        return
    print(f"[ERR] {error}")

# ══════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    if not TOKEN:
        print("❌  Thiếu DISCORD_TOKEN trong .env")
        sys.exit(1)
    if not OBFTOOL_DIR.exists():
        print(f"❌  Không tìm thấy obftool tại: {OBFTOOL_DIR}")
        sys.exit(1)
    bot.run(TOKEN)
