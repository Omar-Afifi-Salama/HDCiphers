"""
hdciphers: A hyper-dynamic encryption and decryption library.
"""

# 1. Versioning
__version__ = "0.1.0"  # Switched to standard semantic versioning (Major.Minor.Patch) for PyPI
__author__ = "Omar Afifi"

# 2. Expose the core entities to the user interface namespace
from .classes import Charset, Text
from .classical import (
    Caesar, ROT13, Atbash, Substitution, Affine, PigLatin, TapCode,
    BaconsCipher, NullCipher, Scytale, RailFence, StraddlingCheckerboard,
    MlecchitaVikalpa, Vigenere, Beaufort, Autokey, RunningKey, AlbertiDisk,
    Playfair, Bifid, Hill, ADFGVX, Nihilist, M94, Chaocipher, VICCipher
)

# 3. Explicitly define what is available when someone uses `from hdciphers import *`
__all__ = [
    "Charset",
    "Text",
    "Caesar", "ROT13", "Atbash", "Substitution", "Affine", "PigLatin", "TapCode",
    "BaconsCipher", "NullCipher", "Scytale", "RailFence", "StraddlingCheckerboard",
    "MlecchitaVikalpa", "Vigenere", "Beaufort", "Autokey", "RunningKey", "AlbertiDisk",
    "Playfair", "Bifid", "Hill", "ADFGVX", "Nihilist", "M94", "Chaocipher", "VICCipher"
]

# 4. Global interactive diagnostic helper utility registration
def help() -> None:
    """Prints an interactive structural catalog overview of the hdciphers engine workspace."""
    print("=" * 70)
    print(f" 🛡️  hdciphers Framework Diagnostic Utility (v{__version__})")
    print("=" * 70)
    print("Welcome, Agent. Below is your directory of available cipher units:\n")
    
    print(" [Tier 1: Monoalphabetic & Steganographic Functional Engines]")
    print("   Caesar, ROT13, Atbash, Substitution, Affine, PigLatin, TapCode, BaconsCipher, NullCipher\n")
    
    print(" [Tier 2: Transposition & Geometrical Planes]")
    print("   Scytale, RailFence, StraddlingCheckerboard, MlecchitaVikalpa\n")
    
    print(" [Tier 3: Polyalphabetic Key Streams & Stateful Automata]")
    print("   Vigenere, Beaufort, Autokey, RunningKey, AlbertiDisk\n")
    
    print(" [Tier 4: Product Ciphers & High-Dimensional Matrices]")
    print("   Playfair, Bifid, Hill, ADFGVX\n")
    
    print(" [Tier 5: Spy-Grade Mechanical Mechanical Wheels & Complex Papers]")
    print("   Nihilist, M94, Chaocipher, VICCipher\n")
    
    print("-" * 70)
    print(" Execution Quick-Start Pattern:")
    print("   >>> import hdciphers as hdc")
    print("   >>> text_space = hdc.Text('secret message', domain_charset=hdc.Charset.english())")
    print("   >>> text_space.encrypt(hdc.Vigenere(keyword='monarch'))")
    print("   >>> print(text_space)")
    print("=" * 70)