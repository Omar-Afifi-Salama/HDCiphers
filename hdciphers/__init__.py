"""
hdciphers: A hyper-dynamic encryption and decryption library.
"""

# 1. Versioning

__version__ = "0.10"
__author__ = "omar Afifi"

# # 2. Expose the core functions to the user

from .classes import Charset, Text
from .classical import Caesar

# # 3. Explicitly define what is available when someone uses `from hdciphers import *`

__all__ = [
    "Charset",
    "Text",
    "Caesar"
]