from __future__ import annotations
from typing import Literal
import unicodedata
# import math

class Charset:

    # TODO think about making charsets immutable
    # TODO think about randomizing them using a seed or maybe do that in the ciphers themselves
    # TODO Adding multiple languages and figure out how to include things like chinese, japanese, etc.
    # TODO Think about adding python optimization tricks

    # --- Constants ---

    ModeType = Literal["both", "upper", "lower"]

    RangeNameType = Literal[
        "english", "european", "cyrillic", "arabic", "greek", 
        "currency", "arrows", "math", "shapes", "dingbats", "chinese"
    ]

    UNICODE_REGISTRY = {
        "english": [(0x0020, 0x007F)],
        "european": [(0x00A0, 0x00FF)],
        "cyrillic": [(0x0400, 0x04FF)],
        "arabic": [(0x0600, 0x06FF)],
        "greek": [(0x0370, 0x03FF)],
        "currency": [(0x20A0, 0x20CF)],
        "arrows": [(0x2190, 0x21FF)],
        "math": [(0x2200, 0x22FF), (0x2A00, 0x2AFF)], # Can combine multiple related ranges
        "shapes": [(0x25A0, 0x25FF)],
        "dingbats": [(0x2700, 0x27BF)],
        "chinese": [(0x4E00, 0x5000)] # Sliced sample of the massive 20,000 block for performance
    }

    # --- Constructor ---
    
    def __init__(self, characters: str, remove_duplicates: bool = True):
        self.chars = "".join(dict.fromkeys(characters)) if remove_duplicates else characters
        # self.length = len(self.chars)

    @property
    def length(self) -> int:
        return len(self.chars)
    
    @property
    def is_unique(self) -> bool:
        """
        Returns True if every character in the current text content is completely unique.
        Useful for analyzing high-entropy cipher text or validating keys.
        """
        # Convert the string into a set of unique characters
        unique_characters = set(self.chars)
        
        # If lengths match, there are no duplicates!
        return len(self.chars) == len(unique_characters)
    
    def get_collisions(self) -> dict[str, int]:
        """
        Returns a dictionary of characters that appear more than once,
        along with their total count.
        """
        from collections import Counter
        
        # Count occurrences of every character
        counts = Counter(self.chars)
        
        # Filter down to only characters that repeat
        collisions = {char: count for char, count in counts.items() if count > 1}
        
        # Return sorted by highest collision rate
        return dict(sorted(collisions.items(), key=lambda item: item[1], reverse=True))
    
    def has_same_chars(self, other: object) -> bool:
        """
        Returns True if both Charsets contain the exact same characters,
        ignoring their internal sequence or order.
        """
        if isinstance(other, Charset):
            return set(self.chars) == set(other.chars)
        elif isinstance(other, str):
            return set(self.chars) == set(other)
        return False

    # --- Pre-defined Modes ---

    @classmethod
    def english(cls, mode: ModeType = "both", include_numbers: bool = False, include_special_chars: bool = False):
        lower = "abcdefghijklmnopqrstuvwxyz"
        upper = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        numbers = "0123456789"
        special_chars = " !@#$%^&*()_+-=[]{}|;':\",./<>?~`"
        
        pool = ""
        if mode in ("lower", "both"): pool += lower
        if mode in ("upper", "both"): pool += upper
        if include_numbers: pool += numbers
        if include_special_chars: pool += special_chars
        return cls(pool)

    @classmethod
    def arabic(cls, include_numbers: bool = False, include_special_chars: bool = False):
        alphabet = "ابتثجحخدذرزسشصضطظعغفقكلمنهوي"
        numbers = "٠١٢٣٤٥٦٧٨٩"
        special_chars = " ؟،؛!@#$%^&*()_+-=[]{}|:',./<>?~`" 
        
        pool = alphabet
        if include_numbers: pool += numbers
        if include_special_chars: pool += special_chars
        return cls(pool)
    
    @classmethod
    def greek(cls, mode: ModeType = "both"):
        lower = "αβγδεζηθικλμνξοπρστυφχψω"
        upper = "ΑΒΓΔΕΖΗΘΙΚΛΜΝΞΟΠΡΣΤΥΦΧΨΩ"
        
        pool = ""
        if mode in ("lower", "both"): pool += lower
        if mode in ("upper", "both"): pool += upper
        return cls(pool)
    
    @classmethod
    def chinese(cls, limit: int = 3000):
        """
        Harvests the most common CJK Unified Ideographs for Mandarin support.
        """
        pool = []
        # The core block for Chinese characters
        start, end = 0x4E00, 0x9FFF 
        
        for codepoint in range(start, end + 1):
            char = chr(codepoint)
            if char.isprintable() and not char.isspace():
                pool.append(char)
                if len(pool) >= limit:
                    break
                    
        return cls("".join(pool))

    @classmethod
    def exotic_pool(cls, limit: int = 400):
        """
        Pure, optimized symbol harvester. Gathers clean Unicode shapes 
        and relies on Charset addition (+) to handle cross-language deduplication.
        """
        unicode_ranges = [
            (0x0390, 0x03FF),  # Greek & Coptic
            (0x20A0, 0x20CF),  # Currency Symbols
            (0x2100, 0x214F),  # Letter-like Symbols
            (0x2190, 0x21FF),  # Arrows
            (0x2200, 0x22FF),  # Mathematical Operators
            (0x25A0, 0x25FF),  # Geometric Shapes
            (0x2A00, 0x2AFF)   # Supplemental Math Operators
        ]
        
        symbols = []
        
        for start, end in unicode_ranges:
            for codepoint in range(start, end + 1):
                char = chr(codepoint)
                
                # Check only for Control characters, Separators, and Stacking Marks
                if unicodedata.category(char)[0] not in ("C", "Z", "M"):
                    symbols.append(char)
                    
                    # Short-circuit loop as soon as we satisfy the requested limit
                    if len(symbols) >= limit:
                        return cls("".join(symbols))
                        
        return cls("".join(symbols))
    
    @classmethod
    def from_ranges(cls, *range_names: RangeNameType, limit_per_range: int = 100):
        """
        Harvests printable characters from specific developer-selected Unicode blocks.
        """
        pool = []
        
        for name in range_names:
            if name not in cls.UNICODE_REGISTRY:
                raise ValueError(f"Unknown block name: '{name}'")
                
            range_list = cls.UNICODE_REGISTRY[name]
            range_chars = []
            
            for start, end in range_list:
                for codepoint in range(start, end + 1):
                    char = chr(codepoint)
                    # if char.isprintable() and not char.isspace():
                    if unicodedata.category(char)[0] not in ("C", "Z", "M"):
                        range_chars.append(char)
            
            # Slice each requested group to prevent one large block from overwhelming others
            pool.extend(range_chars[:limit_per_range])
            
        return cls("".join(pool))

    @classmethod
    def custom(cls, custom_string: str, remove_duplicates: bool = True):
        return cls(custom_string, remove_duplicates)
    
    # --- Unary Dunder Methods ---

    def __str__(self) -> str:
        """What gets shown when a user prints the object: print(charset)"""
        return self.chars

    def __repr__(self) -> str:
        """Returns a syntactically valid string representation of the object."""
        return f"Charset('''{self.chars}''')"

    def __len__(self) -> int:
        """Allows using the native len() function: len(charset)"""
        return self.length

    def __contains__(self, item: object) -> bool:
        """
        Allows using the native 'in' keyword: 'a' in charset
        """
        if isinstance(item, str):
            return item in self.chars
        return False
    
    def __iter__(self):
        """Allows looping directly through characters: for char in charset:"""
        return iter(self.chars)
    
    def __hash__(self) -> int:
        """Allows using Charset objects as keys in dictionaries or elements in sets."""
        return hash(self.chars)
    
    def __getitem__(self, key: int | slice) -> str | "Charset":
        """Allows index slicing and bracket lookups: charset[0] or charset[:5]"""
        if isinstance(key, slice):
            # Returning a new Charset if they slice it ensures it keeps your factory behaviors!
            return Charset(self.chars[key])
        return self.chars[key]

    # --- Binary Dunder Methods ---
    
    def __add__(self, other: object) -> "Charset":
        """
        Combines this Charset with another Charset or a string using '+'.
        Removes duplicates and preserves left-to-right order.
        """
        if isinstance(other, Charset):
            combined_raw = self.chars + other.chars
        elif isinstance(other, str):
            combined_raw = self.chars + other
        else:
            return NotImplemented
            
        return Charset("".join(dict.fromkeys(combined_raw)))

    def __radd__(self, other: object) -> "Charset":
        """
        Handles fallback if a string is on the left side: "abc" + my_charset
        """
        if isinstance(other, str):
            combined_raw = other + self.chars
            return Charset("".join(dict.fromkeys(combined_raw)))
        return NotImplemented
    
    def __sub__(self, other: object) -> "Charset":
        """
        Allows subtracting characters using the '-' operator.
        Removes any characters found in 'other' from this Charset, 
        preserving the original order of the remaining letters.
        """
        if isinstance(other, Charset):
            forbidden_chars = set(other.chars)
        elif isinstance(other, str):
            forbidden_chars = set(other)
        else:
            return NotImplemented

        # Keep characters only if they are NOT in the subtraction pool
        cleaned_chars = [char for char in self.chars if char not in forbidden_chars]
        
        return Charset("".join(cleaned_chars))
    
    def __rsub__(self, other: object) -> "Charset":
        """
        Handles fallback if a raw string is on the left side: "abcdef" - my_charset
        Strips out any characters from the string that exist inside this Charset.
        """
        if isinstance(other, str):
            forbidden_chars = set(self.chars)
            # Filter the raw string, keeping only what is NOT in this charset
            cleaned_chars = [char for char in other if char not in forbidden_chars]
            return Charset("".join(cleaned_chars))
            
        return NotImplemented
    
    def __eq__(self, other: object) -> bool:
        """Allows comparing two charsets: charset1 == charset2"""
        if isinstance(other, Charset):
            return self.chars == other.chars
        return False
    
    def __ne__(self, other: object) -> bool:
        """Allows comparing two charsets: charset1 != charset2"""
        if isinstance(other, Charset):
            return self.chars != other.chars
        return False

    # --- Core Utilities for Ciphers ---

    def contains(self, char: str) -> bool:
        return char in self.chars

    def index_of(self, char: str) -> int:
        return self.chars.index(char)

    def char_at(self, index: int) -> str:
        # Automatically wraps around the chars using modulo arithmetic
        return self.chars[index % self.length]

class Text:
    pass