from .ast_obfuscator  import obfuscate_ast
from .tac_generator   import generate_tac
from .ir_duplicator   import duplicate_ir, mutate_ir
from .cff_engine      import apply_cff
from .mba_transform_v2 import apply_mba_transform
from .string_encryptor import encrypt_strings

__all__ = [
    "obfuscate_ast", "generate_tac", "duplicate_ir", "mutate_ir",
    "apply_cff", "apply_mba_transform", "encrypt_strings",
]
