"""
JoJo's Bizarre Name Generator
==============================
Generates obfuscated Python identifiers themed after JoJo's Bizarre Adventure.
Format: {StandUser}_{Stand}_{Skill}

Used by Stage 1 (AST variable renaming) and Stage 8 (stub variable names).
"""
from __future__ import annotations
import random
import hashlib

# ─── Full JoJo combat table ──────────────────────────────────────────────────

_JOJO_TABLE = [
    # (stand_user, stand_name, [skills])

    # ── Part 3: Stardust Crusaders ────────────────────────────────────────────
    ("Jotaro",      "StarPlatinum",           ["OraOraOra","StarFinger","TimestopPunch","PrecisionAim","TimeStop"]),
    ("Dio",         "TheWorld",               ["ZaWarudo","RoadRoller","KnifeBarrage","BloodSuck","WorldTimeStop"]),
    ("Joseph",      "HermitPurple",           ["ColaBottle","HermitWhip","PhotoDivination","VineGrapple"]),
    ("Avdol",       "MagiciansRed",           ["CrossfireHurricane","RedBind","HeatWave","AnklaCross"]),
    ("Kakyoin",     "HierophantGreen",        ["EmeraldSplash","RemoteBody","GreenBarrier","TenMeterRadius"]),
    ("Polnareff",   "SilverChariot",          ["RapierThrust","ArmorOff","SpeedBoost","FencingStrike"]),

    # ── Part 4: Diamond is Unbreakable ────────────────────────────────────────
    ("Josuke",      "CrazyDiamond",           ["DoraDoraOra","HealRestore","ShardShoot","FixTrap"]),
    ("Kira",        "KillerQueen",            ["PrimaryBomb","SheerHeartAttack","BitesTheDust","AirCompression"]),
    ("Okuyasu",     "TheHand",                ["EraseSpace","SwipeDelete","SpaceCollapse"]),
    ("Koichi",      "Echoes",                 ["SoundStamp","WordFreeze","ThreeFreezeGravity"]),
    ("Rohan",       "HeavensDoor",            ["RewriteMemory","OpenFace","FreezeTarget","ReadSoul"]),

    # ── Part 5: Golden Wind ───────────────────────────────────────────────────
    ("Giorno",      "GoldExperience",         ["LifeGiving","HealWound","TurnObjectToLife"]),
    ("Giorno",      "GoldExperienceRequiem",  ["ReturnToZero","InfiniteDeathLoop","NullifyWill"]),
    ("Bucciarati",  "StickyFingers",          ["ArrivederciZipper","ZipperPortal","ZipperArmor"]),
    ("Abbacchio",   "MoodyBlues",             ["ReplayReality","RecordScene","CopyForm"]),
    ("Mista",       "SexPistols",             ["BulletRedirect","SixShooter","GunControl"]),
    ("Fugo",        "PurpleHaze",             ["VirusRelease","HazeBurst","FleshDissolve"]),
    ("Diavolo",     "KingCrimson",            ["ErasedTime","FutureSight","EpilepticTime"]),
    ("Risotto",     "Metallica",              ["IronExtract","MagnetControl","InvisibleBlade"]),

    # ── Part 6: Stone Ocean ───────────────────────────────────────────────────
    ("Jolyne",      "StoneFree",              ["StringUnravel","StringNet","StoneFreePunch","BodyDissolve","StringGrapple"]),
    ("Pucci",       "Whitesnake",             ["StealMemoryDisc","StealStandDisc","IllusionMaze"]),
    ("Pucci",       "CMoon",                  ["GravityInversion","SurfaceFlip","TurnInsideOut"]),
    ("Pucci",       "MadeInHeaven",           ["TimeAcceleration","UniverseReset","CosmicSpeed"]),
    ("WeatherReport","WeatherReport",         ["LightningCall","HailStorm","RainbowPoison","FogWall"]),
    ("Anasui",      "DiverDown",             ["DeconstructBody","StoreInObject","SpringRelease"]),

    # ── Part 7: Steel Ball Run ────────────────────────────────────────────────
    ("Johnny",      "TuskAct4",              ["InfiniteRotation","WormholeNail","GravityNail"]),
    ("Valentine",   "D4C",                   ["ParallelSwap","LoveTrain","DimensionShield","FlagBarrier"]),
]

# Flatten to list of (user, stand, skill) tuples
_ALL_COMBOS: list[tuple[str, str, str]] = [
    (user, stand, skill)
    for user, stand, skills in _JOJO_TABLE
    for skill in skills
]  # 96 unique combos


# ─── Name generator ──────────────────────────────────────────────────────────

class JoJoNameGenerator:
    """
    Generates identifiers like  Jotaro_StarPlatinum_OraOraOra
    Shuffles the combo pool using the build seed so each obf run
    produces a different mapping. Collision fallback appends _v2, _v3…
    Pool exhaustion falls back to _Stand_{hex} names.
    """

    def __init__(self, seed: int):
        self._rng  = random.Random(seed ^ 0xB1A2E3)
        self._pool = list(_ALL_COMBOS)
        self._rng.shuffle(self._pool)
        self._idx  = 0
        self._used: set[str] = set()

    # ------------------------------------------------------------------
    def next(self, prefix: str = "") -> str:
        """Return the next unique JoJo-themed identifier."""
        while True:
            base = self._pick_base()
            name = base
            ver  = 2
            while name in self._used:
                name = f"{base}_v{ver}"
                ver += 1
            self._used.add(name)
            return name

    # ------------------------------------------------------------------
    def _pick_base(self) -> str:
        if self._idx < len(self._pool):
            user, stand, skill = self._pool[self._idx]
            self._idx += 1
            return f"{user}_{stand}_{skill}"
        # Pool exhausted → deterministic fallback
        h = hashlib.md5(str(self._idx).encode()).hexdigest()[:8]
        self._idx += 1
        return f"_BizarreStand_{h}"


# ─── Emoji bytemap (polymorphic) ─────────────────────────────────────────────

# 272 single-codepoint emoji covering 4 blocks; we slice to 256.
_EMOJI_POOL: list[str] = (
    [chr(c) for c in range(0x1F600, 0x1F650)]   # 80  smileys & people
  + [chr(c) for c in range(0x1F400, 0x1F440)]   # 64  animals
  + [chr(c) for c in range(0x1F300, 0x1F340)]   # 64  weather / nature
  + [chr(c) for c in range(0x1F440, 0x1F470)]   # 48  body parts & fantasy
)[:256]  # exactly 256


def make_emoji_map(seed: int) -> list[str]:
    """
    Return a shuffled list of 256 unique emoji.
    Index = byte value  →  emoji character.
    Different seed → completely different mapping (polymorphic).
    """
    pool = list(_EMOJI_POOL)
    random.Random(seed ^ 0xE0A1B2).shuffle(pool)
    return pool


def encode_bytes_emoji(data: bytes, emoji_map: list[str]) -> str:
    """Encode a bytes object as an emoji string using the given map."""
    return "".join(emoji_map[b] for b in data)
