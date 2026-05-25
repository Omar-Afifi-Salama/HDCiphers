"""
hdciphers: A hyper-dynamic encryption and decryption library.
"""

# 1. Versioning
__version__ = "0.10"
__author__ = "omar Afifi"

# # 2. Expose the core functions to the user
# from .core import encrypt, decrypt
# from .engines import HyperDynamicEngine

from .classes import Charset

# # 3. Explicitly define what is available when someone uses `from hdciphers import *`
# __all__ = [
#     "encrypt",
#     "decrypt",
#     "HyperDynamicEngine",
#     "__version__",
# ]