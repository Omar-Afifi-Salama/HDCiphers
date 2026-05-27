from __future__ import annotations
from typing import Literal
import unicodedata
import math
import shutil
import textwrap
from collections import Counter
import sys
import time
from abc import ABC, abstractmethod

class Charset:

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

    __slots__ = ("chars", "length", "_char_set")
    
    def __init__(self, characters: str, remove_duplicates: bool = True):
        self.chars = "".join(dict.fromkeys(characters)) if remove_duplicates else characters # TODO
        self.length = len(self.chars)
        self._char_set = set(self.chars)

    # @property
    # def length(self) -> int:
    #     return len(self.chars)
    
    @property
    def is_unique(self) -> bool:
        """
        Returns True if every character in the current text content is completely unique.
        Useful for analyzing high-entropy cipher text or validating keys.
        """
        
        return len(self.chars) == len(self._char_set)
    
    def get_collisions(self) -> dict[str, int]:
        """
        Returns a dictionary of characters that appear more than once,
        along with their total count.
        """        
        # Count occurrences of every character
        counts = Counter(self.chars)
        
        # Filter down to only characters that repeat
        collisions = {char: count for char, count in counts.items() if count > 1}
        
        # Return sorted by highest collision rate
        return dict(sorted(collisions.items(), key=lambda item: item[1], reverse=True))
    
    def has_same_chars(self, other: Charset | str) -> bool:
        """
        Returns True if both Charsets contain the exact same characters,
        ignoring their internal sequence or order.
        """
        if isinstance(other, Charset):
            return self._char_set == other._char_set
        elif isinstance(other, str):
            return self._char_set == set(other)
        return False

    def shuffle(self, seed: int | str | None = None) -> "Charset":
        """Returns a new, cryptographically shuffled copy of this Charset."""
        import random

        char_list = list(self.chars)
        # Use a local instance of Random to protect global state determinism
        rng = random.Random(seed)
        rng.shuffle(char_list)
        return Charset("".join(char_list))

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
            return item in self._char_set
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
    
    # def __ne__(self, other: object) -> bool:
    #     """Allows comparing two charsets: charset1 != charset2"""
    #     if isinstance(other, Charset):
    #         return self.chars != other.chars
    #     return False

    # --- Core Utilities for Ciphers ---

    def contains(self, char: str) -> bool:
        return char in self._char_set

    def index_of(self, char: str) -> int:
        return self.chars.index(char)

    def char_at(self, index: int) -> str:
        # Automatically wraps around the chars using modulo arithmetic
        return self.chars[index % self.length]

class Text:

    # --- Constants ---

    Language = Literal["english", "arabic", "chinese", "greek"]
    
    # --- Constructor ---

    __slots__ = ("content", "language", "domain_charset", "range_charset", "_history")
    
    def __init__(self, initial_content: str, language: Language = "english", domain_charset: Charset = None, range_charset: Charset = None):
        self.content = initial_content
        self.domain_charset = domain_charset or Charset.english(mode="upper")
        self.range_charset = range_charset or self.domain_charset
        self.language = language
        self._history = [("Original", initial_content)]

    # --- API ---

    def apply_change(self, cipher_name: str, new_content: str):
        self.content = new_content
        self._history.append((cipher_name, new_content))

    def encrypt(self, cipher_engine: Cipher, visualize: bool = False, delay_seconds: float = 1):
        cipher_engine._run_encrypt(self, visualize, delay_seconds)
        return self
    
    def decrypt(self, cipher_engine: Cipher, visualize: bool = False, delay_seconds: float = 1):
        cipher_engine._run_decrypt(self, visualize, delay_seconds)
        return self
    
    def undo(self, steps: int = 1):
        """Rolls back the encryption layers by popping the history stack."""
        for _ in range(steps):
            if len(self._history) > 1:
                self._history.pop()
                self.content = self._history[-1][1]
            else:
                break

        return self
    
    def unwind(self):
        """
        Automatically reverses every encryption step stored in the history stack,
        returning the text to its original state.
        """
        while len(self._history) > 1:
            self._history.pop()

        self.content = self._history[0][1]
        return self
    
    def get_history(self):
        return self._history

    def print_history(self):
        """
        Prints a custom, spaced layout of the text space's audit trail.
        Dynamically adjusts to fit the terminal width and cleanly wraps content block output.
        """
        # 1. Dynamically read the exact width of the user's terminal console window
        # Falls back to 80 characters if running inside an un-insulated environment or early IDE buffer
        terminal_width = shutil.get_terminal_size(fallback=(80, 20)).columns
        
        print(f"\n[hdciphers] Text Space Audit Trail (Current Length: {len(self.content)})\n")
        
        for i, (action, data) in enumerate(self._history):
            # 2. Print the operation title name
            print(f"Step {i}: {action}")
            print() # Print empty whitespace underneath the operation name
            
            # 3. Cleanly wrap long text payload blocks so they wrap inside the terminal gracefully
            # subsequent_indent='    ' ensures wrapped lines match the starting paragraph margin!
            wrapped_data = textwrap.fill(
                f"'{data}'", 
                width=terminal_width, 
                initial_indent="    ", 
                subsequent_indent="    "
            )
            print(wrapped_data)
            print() # Print empty whitespace underneath the text layout payload
            
            # 4. Draw a dynamic line that matches the edge-to-edge terminal width exactly
            print("=" * terminal_width)
            print() # Print spacing line separation padding

    def normalize_content(self, convert_numbers: bool = False) -> "Text":
        """Cleans content and normalizes it to the current domain."""
        self.content = self._normalize(convert_numbers=convert_numbers)
        self._history.append(("Normalized State", self.content))
        return self

    def _normalize(self, convert_numbers: bool = False, ignore_foreign_chars: bool = True) -> str:
        # Step 1: Handle native number translations based on the language context
        working_content = self.content
        if convert_numbers:
            working_content = ScriptNormalizer.convert_digits(working_content, self.language, self.domain_charset)
        
        normalized_chars = []
        for char in working_content:
            target_char = char
            
            # Step 2: Smart Conversion (Case folding checks)
            if target_char not in self.domain_charset._char_set:
                if target_char.upper() in self.domain_charset._char_set:
                    target_char = target_char.upper()
                elif target_char.lower() in self.domain_charset._char_set:
                    target_char = target_char.lower()

            # Step 3: Final validation filter
            if target_char in self.domain_charset._char_set:
                normalized_chars.append(target_char)
            elif not ignore_foreign_chars:
                raise ValueError(f"Character '{char}' cannot be mapped to the current domain charset.")
                
        return "".join(normalized_chars)
    
    @property
    def metrics(self) -> dict:
        """
        Dynamically analyzes the cryptographic health, information density, 
        and security thresholds of the current text state across any language.
        """
        if not self.content:
            return {
                "entropy": 0.0,
                "security_rating": "0/10",
                "is_lossy_pipeline": False,
                "frequencies": {}
            }

        # DYNAMIC UPGRADE: Instead of hardcoded English .isalpha(), we count 
        # characters relative to what actually belongs in our domain and range!
        total_chars = len(self.content)
        counts = Counter(self.content)
        
        # 1. Calculate true character probabilities
        frequencies = {char: round(count / total_chars, 4) for char, count in counts.items()}
        
        # 2. Dynamic Shannon Entropy calculation: H(X) = -sum(P(x) * log2(P(x)))
        entropy = -sum(p * math.log2(p) for p in frequencies.values())
        
        # 3. Dynamic Security Score Scaler (0/10)
        # Calculate the theoretical max chaos possible for this specific domain size
        domain_len = self.domain_charset.length
        max_entropy = math.log2(domain_len) if domain_len > 1 else 1.0
        
        # Scale current entropy linearly into a 0-10 metric
        # Original plain text naturally scores lower due to linguistic patterns
        security_scaled = (entropy / max_entropy) * 10
        security_rating = f"{min(round(security_scaled, 1), 10.0)}/10"
        
        # 4. Check for structural lossy bottlenecks
        is_lossy = self.range_charset.length < self.domain_charset.length # TODO

        return {
            "length": total_chars,
            "entropy": round(entropy, 4),
            "security_rating": security_rating,
            "is_lossy_pipeline": is_lossy,
            "frequencies": dict(sorted(frequencies.items(), key=lambda item: item[1], reverse=True))
        }
    
    # --- Unary Dunder Methods --- # TODO
    
    def __str__(self) -> str:
        return self.content
    
    def __repr__(self) -> str:
        """
        Returns a syntactically valid Python code string representation.
        Allows reconstructing this exact state by copy-pasting the output.
        """
        # Grab the clean primitive dictionary layout
        state_dict = self.to_dict()
        
        # Format it cleanly as hdc.Text.from_dict(dictionary)
        return f"hdc.Text.from_dict({state_dict})"

    def __len__(self) -> int:
        return len(self.content)
    
    def __getitem__(self, key: int | slice) -> str | "Text":
        """
        Allows index lookups and slicing: text_obj[0] or text_obj[2:5]
        Slicing returns a new Text instance preserving the configuration!
        """
        if isinstance(key, slice):
            return Text(
                initial_content=self.content[key], 
                language=self.language, 
                domain_charset=self.domain_charset, 
                range_charset=self.range_charset
            )
        return self.content[key]

    def __contains__(self, item: object) -> bool:
        """Allows high-speed sub-string membership scans: 'SECRET' in text_obj"""
        if isinstance(item, str):
            return item in self.content
        return False

    def __iter__(self):
        """Allows looping directly through characters: for char in text_obj:"""
        return iter(self.content)
    
    # --- Binary Dunder Methods ---
    
    def __add__(self, other: object) -> "Text":
        """Combines two Text spaces or a Text space and a raw string using '+'."""
        if isinstance(other, Text):
            combined_raw = self.content + other.content
        elif isinstance(other, str):
            combined_raw = self.content + other
        else:
            return NotImplemented
            
        return Text(
            initial_content=combined_raw, 
            language=self.language, 
            domain_charset=self.domain_charset, 
            range_charset=self.range_charset
        )

    def __radd__(self, other: object) -> "Text":
        """Handles fallback if a raw string is on the left side: 'PRE-' + text_obj"""
        if isinstance(other, str):
            combined_raw = other + self.content
            return Text(
                initial_content=combined_raw, 
                language=self.language, 
                domain_charset=self.domain_charset, 
                range_charset=self.range_charset
            )
        return NotImplemented
    
    def __eq__(self, other: object) -> bool:
        """Allows simple string matching: text_obj == 'ATTACK AT DAWN'"""
        if isinstance(other, Text):
            return self.content == other.content
        elif isinstance(other, str):
            return self.content == other
        return False
    
    # --- Saving & Loading Text Object States ---

    def to_dict(self) -> dict:
        """
        Serializes the entire Text space, including its configuration, 
        active state, and full historical pipeline audit trail into a primitive dict.
        """
        return {
            "content": self.content,
            "language": self.language,
            # Extract the raw strings from the immutable Charset engines
            "domain_charset": self.domain_charset.chars,
            "range_charset": self.range_charset.chars,
            # Serialize the history tuples into clean primitive lists
            "history": [[action, data] for action, data in self._history]
        }

    @classmethod
    def from_dict(cls, data: dict) -> "Text":
        """
        Reconstructs a perfect, living Text instance from a serialized dictionary,
        completely restoring its exact historical pipeline and charset environments.
        """
        # 1. Rebuild the core Charset instances from their stored string states
        domain = Charset(data["domain_charset"])
        range_set = Charset(data["range_charset"])
        
        # 2. Instantiate the base Text object using the current active content
        instance = cls(
            initial_content=data["content"],
            language=data["language"],
            domain_charset=domain,
            range_charset=range_set
        )
        
        # 3. Overwrite the default initial history tracking stack with the fully restored database trail
        instance._history = [(action, content) for action, content in data["history"]]
        
        return instance

class ScriptNormalizer:
    """Registry that handles language-specific translations for numbers and symbols."""
    
    # Language-specific digit-to-word mappings
    NUMBER_MAPS = {
        "english": {
            "0": "zero", "1": "one", "2": "two", "3": "three", "4": "four",
            "5": "five", "6": "six", "7": "seven", "8": "eight", "9": "nine"
        },
        "arabic": {
            "0": "صفر", "1": "واحد", "2": "اثنان", "3": "ثلاثة", "4": "أربعة",
            "5": "خمسة", "6": "ستة", "7": "سبعة", "8": "ثمانية", "9": "تسعة",
            "٠": "صفر", "١": "واحد", "٢": "اثنان", "٣": "ثلاثة", "٤": "أربعة",
            "٥": "خمسة", "٦": "ستة", "٧": "سبعة", "٨": "ثمانية", "٩": "تسعة"
        },
        "chinese": {
            "0": "零", "1": "一", "2": "二", "3": "三", "4": "四",
            "5": "五", "6": "六", "7": "七", "8": "八", "9": "九"
        },
        "greek": {
            "0": "μηδεν", "1": "ενα", "2": "δυο", "3": "τρια", "4": "τεσσερα",
            "5": "πεντε", "6": "εξι", "7": "επτα", "8": "οκτω", "9": "εννεα"
        }
    }

    @classmethod
    def convert_digits(cls, text: str, language: str, domain: Charset) -> str:
        """
        Converts raw digits into native word equivalents, dynamically adapting to 
        the casing footprint of the domain across any global script.
        """
        lang_map = cls.NUMBER_MAPS.get(language.lower())
        if not lang_map:
            return text
            
        # DYNAMIC DETECTOR: Count uppercase vs lowercase letters in the active domain
        # This works automatically for English, Greek, Cyrillic, etc.
        upper_count = sum(1 for char in domain.chars if char.isupper())
        lower_count = sum(1 for char in domain.chars if char.islower())
        
        # If the domain is strictly or mostly uppercase, we transform the output
        should_uppercase = upper_count > 0 and upper_count >= lower_count
            
        converted = []
        for char in text:
            if char in lang_map:
                base_word = lang_map[char]
                # Apply uppercase only if the domain layout actively demands it
                converted.append(base_word.upper() if should_uppercase else base_word)
            else:
                converted.append(char)
                
        return "".join(converted)

class CipherVisualizer:
    """
    Centralized visualization routing matrix. Houses the animation engines 
    and dynamically binds them to incoming ciphers.
    """

    # Encapsulated environment detection inside the class scope
    try:
        from IPython.display import clear_output
        _IN_JUPYTER = True
    except ImportError:
        _IN_JUPYTER = False

    Types = Literal["substitution", "polyalphabetic", "transposition"]

    # Central registry: Maps a cipher's classification to its UI engine method
    STRATEGY_MAP = {
        "substitution": lambda inst, txt, dom, rng, dir, delay: CipherVisualizer.animate_substitution(inst, txt, dom, rng, dir, delay),
        "polyalphabetic": lambda inst, txt, dom, rng, dir, delay: CipherVisualizer.animate_keystream(inst, txt, dom, rng, dir, delay),
        "transposition": lambda inst, txt, dom, rng, dir, delay: CipherVisualizer.animate_grid(inst, txt, dom, rng, dir, delay),
    }

    @classmethod
    def animate_substitution(cls, cipher_instance, plaintext: str, domain: "Charset", range_set: "Charset", direction: str, delay_seconds: float = 0.1) -> str:
        """Universal, clean animation stream engine for monoalphabetic ciphers."""
        result = []
        total_chars = len(plaintext)
        PREVIEW_LIMIT = 20
        
        label_in = "Input" if direction == "encrypt" else "Ciphertext"
        label_out = "Output" if direction == "encrypt" else "Plaintext"
        math_func = getattr(cipher_instance, direction)

        for i, char in enumerate(plaintext):
            single_output = math_func(char, domain, range_set)
            result.append(single_output)
            
            if i < PREVIEW_LIMIT:
                cls._render_frame(
                    cipher_instance, plaintext, result, i, total_chars, 
                    PREVIEW_LIMIT, label_in, label_out, char, single_output, direction,
                    domain, range_set
                )
                # Increasing delay_seconds directly increases the loop wait time
                time.sleep(delay_seconds)
            elif i == PREVIEW_LIMIT:
                print(f"Fast-forwarding remaining {total_chars - PREVIEW_LIMIT} characters...")
                
        print(f"Status: {direction.capitalize()} sequence execution complete.\n")
        return math_func(plaintext, domain, range_set)

    @classmethod
    def _render_frame(cls, cipher_instance, plaintext: str, result: list[str], idx: int, total: int, limit: int, lbl_in: str, lbl_out: str, current_in: str, current_out: str, direction: str, domain: "Charset", range_set: "Charset"):
        """Uses IPython cells to update display frames with bidirectional index tracking."""
        
        if cls._IN_JUPYTER:
            from IPython.display import clear_output
            clear_output(wait=True)
            
        print(f"[hdciphers] Algorithm: {cipher_instance.__class__.__name__} ({direction.upper()})")
        print("-" * 60)

        is_cropped = total > limit
        visible_in = plaintext[:limit] + ("..." if is_cropped else "")
        pointer_row = "".join(["^" if i == idx else " " for i in range(min(total, limit))])
        
        current_preview = "".join(result[:limit]) + plaintext[idx+1:limit]
        if is_cropped: 
            current_preview += "..."

        print(f"{lbl_in:<12}: {visible_in}")
        print(f"              {pointer_row}")
        print(f"{lbl_out:<12}: {current_preview}")
        print("-" * 60)

        # FIXED: Assign source and target maps safely using the parameters passed from the loop
        source_set = domain if direction == "encrypt" else range_set
        target_set = range_set if direction == "encrypt" else domain
        
        if current_in in source_set and current_out in target_set:
            in_idx = source_set.index_of(current_in)
            out_idx = target_set.index_of(current_out)
            
            start_slice = max(0, in_idx - 3)
            end_slice = min(source_set.length, in_idx + 4)
            alphabet_ribbon = source_set.chars[start_slice:end_slice]
            ribbon_pointer = "".join(["|" if i == (in_idx - start_slice) else " " for i in range(len(alphabet_ribbon))])
            
            print(f"Mapping Matrix :  ... {alphabet_ribbon} ...")
            print(f"                       {ribbon_pointer}")
            print(f"Transformation :  {current_in} (Index {in_idx:<2}) -> {current_out} (Index {out_idx})")
        else:
            print("Mapping Matrix :  [Character bypassed normalization checks]")
            print(f"Transformation :  {current_in} -> {current_out} (Pass-through)")

        print("-" * 60)
        sys.stdout.flush()

    @classmethod
    def animate_keystream(cls, cipher_instance, plaintext: str, domain: "Charset", range_set: "Charset", direction: str, delay_seconds: float = 0.1) -> str:
        """Universal visual streaming window optimized for polyalphabetic keystreams."""
        result = []
        total_chars = len(plaintext)
        PREVIEW_LIMIT = 20
        
        label_in = "Input" if direction == "encrypt" else "Ciphertext"
        label_out = "Output" if direction == "encrypt" else "Plaintext"
        math_func = getattr(cipher_instance, direction)

        # Reconstruct the exact keystream sequence used by the cipher instance
        # We look up the keyword or stream config safely from the instance
        if hasattr(cipher_instance, "book_stream"):
            raw_stream = cipher_instance.book_stream
        elif hasattr(cipher_instance, "keyword"):
            if cipher_instance.__class__.__name__ == "Autokey" and direction == "encrypt":
                clean_plain = [c for c in plaintext if c in domain]
                raw_stream = cipher_instance.keyword + "".join(clean_plain)
            else:
                raw_stream = cipher_instance.keyword
        else:
            raw_stream = "constant"

        for i, char in enumerate(plaintext):
            # Run single character math via the cipher engine
            single_output = math_func(char, domain, range_set)
            result.append(single_output)
            
            if i < PREVIEW_LIMIT:
                # Generate a padded list showing the keystream aligned with the input
                if raw_stream == "constant":
                    current_key_char = "-"
                elif cipher_instance.__class__.__name__ == "Autokey" and direction == "decrypt":
                    # Autokey decryption generates the stream dynamically, so we copy that logic
                    current_stream = list(cipher_instance.keyword) + result[:-1]
                    current_key_char = current_stream[i] if i < len(current_stream) else "-"
                else:
                    current_key_char = raw_stream[i % len(raw_stream)]

                cls._render_keystream_frame(
                    cipher_instance, plaintext, result, i, total_chars, 
                    PREVIEW_LIMIT, label_in, label_out, char, single_output, 
                    direction, current_key_char, raw_stream
                )
                time.sleep(delay_seconds)
            elif i == PREVIEW_LIMIT:
                print(f"Fast-forwarding remaining {total_chars - PREVIEW_LIMIT} characters...")
                
        print(f"Status: Polyalphabetic {direction} execution complete.\n")
        return math_func(plaintext, domain, range_set)

    @staticmethod
    def _render_keystream_frame(cipher_instance, plaintext: str, result: list[str], idx: int, total: int, limit: int, lbl_in: str, lbl_out: str, current_in: str, current_out: str, direction: str, key_char: str, raw_stream: str):
        """Renders an aligned 3-row telemetry frame tracking text, keystream, and shifts."""
        if CipherVisualizer._IN_JUPYTER:
            from IPython.display import clear_output
            clear_output(wait=True)
            
        print(f"[hdciphers] Polyalphabetic Stream: {cipher_instance.__class__.__name__} ({direction.upper()})")
        print("-" * 60)

        is_cropped = total > limit
        visible_in = plaintext[:limit] + ("..." if is_cropped else "")
        pointer_row = "".join(["^" if i == idx else " " for i in range(min(total, limit))])
        
        current_preview = "".join(result[:limit]) + plaintext[idx+1:limit]
        if is_cropped: 
            current_preview += "..."

        # Generate a visible slice of the repeating/running keystream aligned to the input width
        visible_key = []
        for i in range(min(total, limit)):
            if plaintext[i] == ' ':
                visible_key.append(" ")
            else:
                if raw_stream == "constant":
                    visible_key.append("-")
                elif cipher_instance.__class__.__name__ == "Autokey" and direction == "decrypt":
                    curr = list(cipher_instance.keyword) + result[:i]
                    visible_key.append(curr[i] if i < len(curr) else "-")
                else:
                    visible_key.append(raw_stream[i % len(raw_stream)])
        visible_key_str = "".join(visible_key) + ("..." if is_cropped else "")

        print(f"{lbl_in:<12}: {visible_in}")
        print(f"Keystream   : {visible_key_str}")
        print(f"              {pointer_row}")
        print(f"{lbl_out:<12}: {current_preview}  (Key: '{key_char}' -> {current_in} to {current_out})")
        print("-" * 60)
        sys.stdout.flush()

    @classmethod
    def animate_grid(cls, cipher_instance, plaintext: str, domain: "Charset", range_set: "Charset", direction: str, delay_seconds: float = 0.5) -> str:
        """Matrix snapshot engine optimized for structural transposition geometries."""
        # Transposition structures are chunk-heavy. We can show the operational transition 
        # from raw state to the fully transposed geometric matrix layout.
        if cls._IN_JUPYTER:
            from IPython.display import clear_output
            clear_output(wait=True)

        print(f"[hdciphers] Transposition Matrix: {cipher_instance.__class__.__name__} ({direction.upper()})")
        print("-" * 60)
        print(f"Source Input Block : '{plaintext}'")
        print("Processing geometric indexes...")
        sys.stdout.flush()
        time.sleep(delay_seconds)

        # Trigger the math directly to extract final structural boundaries
        math_func = getattr(cipher_instance, direction)
        final_output = math_func(plaintext, domain, range_set)

        if cls._IN_JUPYTER:
            clear_output(wait=True)

        print(f"[hdciphers] Transposition Matrix: {cipher_instance.__class__.__name__} ({direction.upper()})")
        print("-" * 60)
        print(f"Source Input Matrix : '{plaintext}'")
        print()
        
        # Custom structural visualization tailored dynamically to the active cipher geometric type
        name = cipher_instance.__class__.__name__
        if name == "Scytale" or name == "Columnar":
            import math
            diameter = getattr(cipher_instance, "diameter", 4)
            cols = math.ceil(len(plaintext) / diameter)
            padded = plaintext.ljust(cols * diameter, ' ')
            
            print("--- Geometrical Grid Layout ---")
            for r in range(diameter):
                row_slice = [padded[r * cols + c] for c in range(cols)]
                print(f"  Row {r}:  [ " + " | ".join(row_slice) + " ]")
            print()
            
        elif name == "Rail Fence":
            rails = getattr(cipher_instance, "rails", 3)
            fence = [[' ' for _ in range(len(plaintext))] for _ in range(rails)]
            rail, direction_sign = 0, 1
            for i, char in enumerate(plaintext):
                fence[rail][i] = char if direction == "encrypt" else "*"
                rail += direction_sign
                if rail == 0 or rail == rails - 1: direction_sign *= -1
            
            print("--- Active Rail Tracking Path ---")
            for row in fence:
                print("  " + " ".join(row))
            print()
            
        elif name == "CardGrille":
            print("--- 2D Rotational Array Plane ---")
            chunks = [plaintext[i:i+16].ljust(16, ' ') for i in range(0, len(plaintext), 16)]
            for idx, chunk in enumerate(chunks):
                print(f" Block {idx}:")
                for r in range(4):
                    print("    " + " | ".join(list(chunk[r*4:(r+1)*4])))
            print()

        print(f"Transposed Output   : '{final_output}'")
        print("-" * 60)
        sys.stdout.flush()

        return final_output

class Cipher(ABC):
    
    classification: CipherVisualizer.Types = None

    is_fractionating: bool = False

    def _run_encrypt(self, text_obj: Text, visualize: bool = False, delay_seconds: float = 1):

        if text_obj.domain_charset.length != text_obj.range_charset.length and not self.is_fractionating:
            print(f"[Warning] Charset size mismatch! Domain ({text_obj.domain_charset.length} chars) "
                  f"does not match Range ({text_obj.range_charset.length} chars). "
                  f"Decryption data loss may occur.")
        
        if visualize:
            # Look up the strategy in our dictionary and fire it with direction="encrypt"
            visualizer_func = CipherVisualizer.STRATEGY_MAP.get(self.classification)
            new_str = visualizer_func(self, text_obj.content, text_obj.domain_charset, text_obj.range_charset, "encrypt", delay_seconds)
        else:
            new_str = self.encrypt(text_obj.content, text_obj.domain_charset, text_obj.range_charset)
        
        text_obj.apply_change(f"Encrypted via {self.__class__.__name__}", new_str)

    def _run_decrypt(self, text_obj: Text, visualize: bool = False, delay_seconds: float = 1):
        # Now decryption fully supports the exact same optional visualizer stream!
        if visualize:
            # Fire the exact same strategy mapping but with direction="decrypt"
            visualizer_func = CipherVisualizer.STRATEGY_MAP.get(self.classification)
            new_str = visualizer_func(self, text_obj.content, text_obj.domain_charset, text_obj.range_charset, "decrypt", delay_seconds)
        else:
            new_str = self.decrypt(text_obj.content, text_obj.domain_charset, text_obj.range_charset)
        
        text_obj.apply_change(f"Decrypted via {self.__class__.__name__}", new_str)

    @abstractmethod
    def encrypt(self, plaintext: str, domain: Charset, range_set: Charset) -> str:
        pass
    
    @abstractmethod
    def decrypt(self, ciphertext: str, domain: Charset, range_set: Charset) -> str:
        pass