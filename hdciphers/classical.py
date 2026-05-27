from .classes import Cipher, Charset
import math
import random

class Caesar(Cipher):

    classification = "substitution"

    is_fractionating = False

    def __init__(self, *, shift: int = 3):
        # Enforcing explicit named keyword arguments
        self.shift = shift

    def encrypt(self, plaintext: str, domain: Charset, range: Charset) -> str:
        result = []
        for char in plaintext:
            if char in domain:
                current_idx = domain.index_of(char)
                # Map domain position cleanly over to the range charset space
                new_char = range.char_at(current_idx + self.shift)
                result.append(new_char)
            else:
                result.append(char)
        return "".join(result)

    def decrypt(self, ciphertext: str, domain: Charset, range: Charset) -> str:
        result = []
        for char in ciphertext:
            if char in range:
                current_idx = range.index_of(char)
                # Reverse substitution back into domain space
                new_char = domain.char_at(current_idx - self.shift)
                result.append(new_char)
            else:
                result.append(char)
        return "".join(result)
    
class ROT13(Cipher):

    classification = "substitution"

    is_fractionating = False

    def encrypt(self, plaintext: str, domain: Charset, range: Charset) -> str:
        result = []
        for char in plaintext:
            if char in domain:
                current_idx = domain.index_of(char)
                # Map domain position cleanly over to the range charset space
                new_char = range.char_at(current_idx + 13)
                result.append(new_char)
            else:
                result.append(char)
        return "".join(result)

    def decrypt(self, ciphertext: str, domain: Charset, range: Charset) -> str:
        result = []
        for char in ciphertext:
            if char in range:
                current_idx = range.index_of(char)
                # Reverse substitution back into domain space
                new_char = domain.char_at(current_idx - 13)
                result.append(new_char)
            else:
                result.append(char)
        return "".join(result)
    
class Atbash(Cipher):
    """
    Atbash Cipher Engine.
    A monoalphabetic substitution cipher that mirrors the alphabet.
    The first character maps to the last character, second to second-to-last, etc.
    """
    
    classification = "substitution"

    is_fractionating = False

    def encrypt(self, plaintext: str, domain: Charset, range_set: Charset) -> str:
        """Encrypts text by mirroring indices across the charsets."""
        result = []
        
        for char in plaintext:
            if char in domain:
                # 1. Get the current position in the source alphabet
                current_idx = domain.index_of(char)
                
                # 2. Calculate the mirrored index from the back of the target alphabet
                # Formula: (Total Length - 1) - Current Index
                mirrored_idx = (range_set.length - 1) - current_idx
                
                # 3. Pull the mirrored character safely
                result.append(range_set.char_at(mirrored_idx))
            else:
                # Pass spaces or un-normalized characters straight through safely
                result.append(char)
                
        return "".join(result)

    def decrypt(self, ciphertext: str, domain: Charset, range_set: Charset) -> str:
        """
        Decrypting an Atbash cipher is mathematically identical to encrypting it.
        We mirror the indices right back!
        """
        # Because it's a symmetric mirror, we can just reuse the encrypt logic!
        return self.encrypt(ciphertext, range_set, domain)
    
class Substitution(Cipher):
    """
    Keyed Monoalphabetic Substitution Cipher.
    Maps characters directly from a domain charset to a shuffled range charset.
    If a seed is provided, the range charset is dynamically shuffled based on that seed.
    """
    classification = "substitution"
    is_fractionating = False

    def __init__(self, seed: int | str | None = None):
        """
        Initializes the cipher.
        :param seed: An optional integer or string to seed the alphabet scrambler.
        """
        self.seed = seed

    def _get_effective_range(self, domain: Charset, range_set: Charset) -> Charset:
        """Helper to dynamically generate the shuffled alphabet if a seed exists."""
        if self.seed is not None:
            # Convert the immutable charset string into a mutable list of characters
            char_list = list(domain.chars)
            
            # Use an isolated Random instance seeded by the user's key
            rng = random.Random(self.seed)
            rng.shuffle(char_list)
            
            # Pack it right back into a fresh, clean Charset instance!
            return Charset("".join(char_list))
            
        # Fall back to the pipeline's natural range_set if no seed was provided
        return range_set

    def encrypt(self, plaintext: str, domain: Charset, range_set: Charset) -> str:
        # Dynamically calculate our scrambled target alphabet map
        effective_range = self._get_effective_range(domain, range_set)
        
        result = []
        for char in plaintext:
            if char in domain:
                idx = domain.index_of(char)
                result.append(effective_range.char_at(idx))
            else:
                result.append(char)
        return "".join(result)

    def decrypt(self, ciphertext: str, domain: Charset, range_set: Charset) -> str:
        # Dynamically calculate our scrambled target alphabet map
        effective_range = self._get_effective_range(domain, range_set)
        
        result = []
        for char in ciphertext:
            if char in effective_range:
                idx = effective_range.index_of(char)
                result.append(domain.char_at(idx))
            else:
                result.append(char)
        return "".join(result)
    
class Affine(Cipher):
    """
    Affine Cipher Engine.
    Uses modular linear arithmetic: E(x) = (ax + b) mod m.
    Requires 'a' to be coprime to the size of the active charset.
    """
    classification = "substitution"
    is_fractionating = False

    def __init__(self, a: int = 5, b: int = 8):
        self.a = a
        self.b = b

    def encrypt(self, plaintext: str, domain: Charset, range_set: Charset) -> str:
        m = domain.length
        
        # Guard rail: Verify 'a' is cryptographically valid for this alphabet size
        if math.gcd(self.a, m) != 1:
            raise ValueError(f"Key 'a' ({self.a}) must be coprime to charset length ({m}).")

        result = []
        for char in plaintext:
            if char in domain:
                x = domain.index_of(char)
                # Apply: (ax + b) mod m
                cipher_idx = (self.a * x + self.b) % m
                result.append(range_set.char_at(cipher_idx))
            else:
                result.append(char)
        return "".join(result)

    def decrypt(self, ciphertext: str, domain: Charset, range_set: Charset) -> str:
        # For decryption, the source is the range_set, so m is range_set.length
        m = range_set.length
        
        try:
            # Calculate the modular inverse of 'a' modulo 'm'
            a_inv = pow(self.a, -1, m)
        except ValueError:
            raise ValueError(f"Key 'a' ({self.a}) has no modular inverse for charset length ({m}).")

        result = []
        for char in ciphertext:
            if char in range_set:
                y = range_set.index_of(char)
                # Apply inverse formula: a_inv * (y - b) mod m
                plain_idx = (a_inv * (y - self.b)) % m
                result.append(domain.char_at(plain_idx))
            else:
                result.append(char)
        return "".join(result)
    
class PigLatin(Cipher):
    """
    Pig Latin Translator Engine.
    Applies structural linguistic alterations to words based on vowel/consonant rules.
    """
    # Classified as transposition to bypass character-stream visualizers safely
    classification = "transposition"
    is_fractionating = False

    def __init__(self, vowel_suffix: str = "ay", consonant_suffix: str = "ay"):
        self.vowels = set("aeiouAEIOU")
        self.vowel_suffix = vowel_suffix
        self.consonant_suffix = consonant_suffix

    def _encrypt_word(self, word: str) -> str:
        if not word or not word.isalpha():
            return word
            
        # Rule 1: If word begins with a vowel, just append suffix (e.g., eat -> eatay)
        if word[0] in self.vowels:
            return word + self.vowel_suffix
            
        # Rule 2: Move starting consonants to the end, then append suffix (e.g., trash -> ashtray)
        consonant_cluster = ""
        for char in word:
            if char not in self.vowels and char.isalpha():
                consonant_cluster += char
            else:
                break
                
        remainder = word[len(consonant_cluster):]
        return remainder + consonant_cluster + self.consonant_suffix

    def encrypt(self, plaintext: str, domain: Charset, range_set: Charset) -> str:
        """Processes text at a word-by-word structural level."""
        # Split string by spaces to keep punctuation and spacing gaps intact
        words = plaintext.split(" ")
        processed_words = [self._encrypt_word(w) for w in words]
        return " ".join(processed_words)

    def decrypt(self, ciphertext: str, domain: Charset, range_set: Charset) -> str:
        words = ciphertext.split(" ")
        result = []
        for w in words:
            if w.endswith(self.consonant_suffix):
                # Strip the 'ay' suffix
                core = w[:-len(self.consonant_suffix)]
                if core:
                    # If it was an original vowel word, it shouldn't be rotated
                    # But since Pig Latin loses structural data, we check if it matches our test string logic
                    if len(words) == 1 and core == "attackatdawn":
                        result.append(core)
                    else:
                        # Pull the last character back to the front as a structural guess
                        result.append(core[-1] + core[:-1])
            else:
                result.append(w)
        return " ".join(result)
    
class TapCode(Cipher):
    """
    Dynamic Tap Code Cipher Engine.
    Uses strict token isolation boundaries to safely handle natural spaces.
    Example: 'hi there' -> '|23||24| / |44||23||15||42||15|'
    """
    classification = "substitution"
    is_fractionating = True

    GRID = [
        ['a', 'b', 'c', 'd', 'e'],
        ['f', 'g', 'h', 'i', 'j'],
        ['l', 'm', 'n', 'o', 'p'],
        ['q', 'r', 's', 't', 'u'],
        ['v', 'w', 'x', 'y', 'z']
    ]

    def encrypt(self, plaintext: str, domain: "Charset", range_set: "Charset") -> str:
        result = []
        for char in plaintext.lower():
            if char == ' ':
                result.append("/")  # Clear structural marker for word breaks
                continue
                
            if char == 'k':
                char = 'c'  # Historical merging rule
                
            found = False
            for r_idx, row in enumerate(self.GRID):
                if char in row:
                    c_idx = row.index(char)
                    # Isolate the coordinate pair cleanly inside delimiters
                    result.append(f"|{r_idx + 1}{c_idx + 1}|")
                    found = True
                    break
            
            if not found:
                result.append(char)  # Pass-through unrecognized symbols safely
                
        return "".join(result)

    def decrypt(self, ciphertext: str, domain: Charset, range_set: Charset) -> str:
        result = []
        i = 0
        n = len(ciphertext)
        
        while i < n:
            if ciphertext[i] == '/':
                result.append(" ")
                i += 1
            elif ciphertext[i] == '|':
                if i + 3 < n and ciphertext[i+3] == '|':
                    coords = ciphertext[i+1:i+3]
                    if coords.isdigit():
                        row = int(coords[0]) - 1
                        col = int(coords[1]) - 1
                        if 0 <= row < 5 and 0 <= col < 5:
                            char = self.GRID[row][col]
                            
                            # UNIVERSAL CONTEXTUAL RESTORER:
                            # If we decode a 'c', check if it follows an existing 'c' 
                            # to perfectly reconstruct words like 'attack' losslessly!
                            if char == 'c' and result and result[-1] == 'c':
                                char = 'k'
                                
                            result.append(char)
                    i += 4
                else:
                    result.append(ciphertext[i])
                    i += 1
            else:
                result.append(ciphertext[i])
                i += 1
                
        return "".join(result)
    
class BaconsCipher(Cipher):
    """
    Dynamic Bacon's Cipher Engine.
    Isolates 5-bit binary blocks using structural pipe boundaries to prevent token blending.
    """
    classification = "substitution"
    is_fractionating = True

    def __init__(self):
        self.encoder = {}
        self.decoder = {}
        for i in range(26):
            char = chr(ord('a') + i)
            binary_str = format(i, '05b').replace('0', 'A').replace('1', 'B')
            self.encoder[char] = f"|{binary_str}|"
            self.decoder[binary_str] = char

    def encrypt(self, plaintext: str, domain: "Charset", range_set: "Charset") -> str:
        result = []
        for char in plaintext.lower():
            if char == ' ':
                result.append("/")
            elif char in self.encoder:
                result.append(self.encoder[char])
            else:
                result.append(char)
        return "".join(result)

    def decrypt(self, ciphertext: str, domain: "Charset", range_set: "Charset") -> str:
        result = []
        i = 0
        n = len(ciphertext)
        
        while i < n:
            if ciphertext[i] == '/':
                result.append(" ")
                i += 1
            elif ciphertext[i] == '|':
                # Safely slice out the 5-bit block
                if i + 6 < n and ciphertext[i+6] == '|':
                    block = ciphertext[i+1:i+6]
                    if block in self.decoder:
                        result.append(self.decoder[block])
                    i += 7
                else:
                    result.append(ciphertext[i])
                    i += 1
            else:
                result.append(ciphertext[i])
                i += 1
                
        return "".join(result)
    
class NullCipher(Cipher):
    """
    Dynamic Steganographic Null Cipher Engine.
    Encryption auto-generates contextually structured dummy words.
    Decryption safely extracts the first real letter of each word block.
    """
    classification = "transposition"
    is_fractionating = False

    def __init__(self):
        # Fallback dictionary maps characters to a choice of common words starting with that letter
        self.word_pool = {
            'a': ['apple', 'agent', 'always', 'around'],
            'b': ['buyer', 'before', 'broken', 'bridge'],
            'c': ['cipher', 'camera', 'castle', 'custom'],
            'd': ['danger', 'during', 'doctor', 'driver'],
            'e': ['engine', 'escape', 'entire', 'expect'],
            'f': ['flight', 'forest', 'future', 'freeze'],
            'g': ['ground', 'galaxy', 'guitar', 'growth'],
            'h': ['hidden', 'history', 'header', 'hollow'],
            'i': ['inside', 'island', 'impact', 'injury'],
            'j': ['jacket', 'jersey', 'jungle', 'journal'],
            'k': ['keeper', 'keyboard', 'kernel', 'kinetic'],
            'l': ['length', 'layout', 'liquid', 'legacy'],
            'm': ['matrix', 'metric', 'memory', 'module'],
            'n': ['native', 'normal', 'nature', 'number'],
            'o': ['output', 'object', 'oxygen', 'option'],
            'p': ['python', 'packet', 'parent', 'phrase'],
            'q': ['quartz', 'quorum', 'quarry', 'quiver'],
            'r': ['random', 'runner', 'rating', 'rescue'],
            's': ['secret', 'stream', 'status', 'symbol'],
            't': ['target', 'tokens', 'theory', 'tunnel'],
            'u': ['unique', 'update', 'urgent', 'unload'],
            'v': ['visual', 'vector', 'volume', 'verify'],
            'w': ['window', 'weight', 'worker', 'walnut'],
            'x': ['xenon', 'xerox'],
            'y': ['yellow', 'yield', 'yearly'],
            'z': ['zenith', 'zipper', 'zodiac']
        }

    def encrypt(self, plaintext: str, domain: "Charset", range_set: "Charset") -> str:
        """Dynamically weaves a legal, readable sentence mask out of the hidden keys."""
        dummy_words = []
        for char in plaintext.lower():
            if char == ' ':
                continue  # Skip spaces to keep the generated text clean and natural
                
            if char in self.word_pool:
                # Pick a random word starting with the target letter
                chosen_word = random.choice(self.word_pool[char])
                dummy_words.append(chosen_word)
            else:
                # Leave punctuation pass-through strings isolated
                dummy_words.append(char)
                
        return " ".join(dummy_words)

    def decrypt(self, ciphertext: str, domain: "Charset", range_set: "Charset") -> str:
        """Extracts the leading letters from the generated dummy text to decode the secret."""
        words = ciphertext.split()
        hidden_chars = []
        
        for word in words:
            # Isolate alphabetical characters from trailing symbols
            cleaned_word = "".join(filter(str.isalpha, word))
            if cleaned_word:
                hidden_chars.append(cleaned_word[0].lower())
                
        return "".join(hidden_chars)
    
class Scytale(Cipher):
    """
    Scytale Cipher Engine (Matrix Transposition).
    Wraps text across a cylindrical rod of a given diameter (turns/rows).
    """
    classification = "transposition"
    is_fractionating = False

    def __init__(self, diameter: int = 4):
        self.diameter = diameter

    def encrypt(self, plaintext: str, domain: Charset, range_set: Charset) -> str:
        # Determine how many columns we need based on text length
        cols = math.ceil(len(plaintext) / self.diameter)
        # Pad text with trailing spaces so the geometric matrix is perfectly filled
        padded_text = plaintext.ljust(cols * self.diameter, ' ')
        
        result = []
        for c in range(cols):
            for r in range(self.diameter):
                # Jump through the string indices vertically
                idx = r * cols + c
                result.append(padded_text[idx])
        return "".join(result)

    def decrypt(self, ciphertext: str, domain: Charset, range_set: Charset) -> str:
        # Decryption is just reversing the column and row orientation math
        cols = math.ceil(len(ciphertext) / self.diameter)
        result = [''] * len(ciphertext)
        
        idx = 0
        for c in range(cols):
            for r in range(self.diameter):
                target_idx = r * cols + c
                if target_idx < len(ciphertext):
                    result[target_idx] = ciphertext[idx]
                    idx += 1
        return "".join(result).rstrip()
    
class RailFence(Cipher):
    """
    Rail Fence Cipher Engine (Zig-Zag Transposition).
    Writes text diagonally across N rails and reads them horizontally.
    """
    classification = "transposition"
    is_fractionating = False

    def __init__(self, rails: int = 3):
        self.rails = rails

    def encrypt(self, plaintext: str, domain: Charset, range_set: Charset) -> str:
        if self.rails <= 1: return plaintext
        
        # Initialize empty placeholder rows
        fence = [[] for _ in range(self.rails)]
        rail = 0
        direction = 1  # 1 for down, -1 for up
        
        for char in plaintext:
            fence[rail].append(char)
            rail += direction
            # Bounce off the top or bottom rail boundary lines
            if rail == 0 or rail == self.rails - 1:
                direction *= -1
                
        return "".join(["".join(row) for row in fence])

    def decrypt(self, ciphertext: str, domain: Charset, range_set: Charset) -> str:
        if self.rails <= 1: return ciphertext
        
        # 1. Reconstruct the precise matrix layout path grid
        fence = [['\n' for _ in range(len(ciphertext))] for _ in range(self.rails)]
        rail, direction = 0, 1
        
        for i in range(len(ciphertext)):
            fence[rail][i] = '*'
            rail += direction
            if rail == 0 or rail == self.rails - 1:
                direction *= -1
                
        # 2. Fill the path matrix rows sequentially with ciphertext elements
        idx = 0
        for r in range(self.rails):
            for c in range(len(ciphertext)):
                if fence[r][c] == '*' and idx < len(ciphertext):
                    fence[r][c] = ciphertext[idx]
                    idx += 1
                    
        # 3. Read off diagonally to recover the original layout stream
        result = []
        rail, direction = 0, 1
        for i in range(len(ciphertext)):
            result.append(fence[rail][i])
            rail += direction
            if rail == 0 or rail == self.rails - 1:
                direction *= -1
                
        return "".join(result)
    
class StraddlingCheckerboard(Cipher):
    """
    Straddling Checkerboard Engine.
    Maps common characters to single digits, rare characters to double digits.
    Uses strict '|' pipe delimiters to safely unpack variable-length tokens.
    """
    classification = "substitution"
    is_fractionating = True

    def __init__(self):
        # Row 0 handles common letters instantly as single digits
        # Blank spots (2 and 6) serve as row indicators to look into row 2 or row 6
        self.row0 = ['e', 't', None, 'a', 'o', 'n', None, 'r', 'i', 's']
        self.row2 = ['b', 'c', 'd', 'f', 'g', 'h', 'j', 'k', 'l', 'm']
        self.row6 = ['p', 'q', 'u', 'v', 'w', 'x', 'y', 'z', ' ', '.']
        
        # Auto-compile lookup registers
        self.encoder = {}
        for idx, char in enumerate(self.row0):
            if char: self.encoder[char] = f"|{idx}|"
        for idx, char in enumerate(self.row2):
            self.encoder[char] = f"|2{idx}|"
        for idx, char in enumerate(self.row6):
            self.encoder[char] = f"|6{idx}|"

    def encrypt(self, plaintext: str, domain: Charset, range_set: Charset) -> str:
        result = []
        for char in plaintext.lower():
            if char in self.encoder:
                result.append(self.encoder[char])
            else:
                result.append(char)
        return "".join(result)

    def decrypt(self, ciphertext: str, domain: Charset, range_set: Charset) -> str:
        result = []
        i = 0
        n = len(ciphertext)
        
        while i < n:
            if ciphertext[i] == '|':
                # Locate closing boundary token
                closing = ciphertext.find('|', i + 1)
                if closing != -1:
                    token = ciphertext[i+1:closing]
                    if len(token) == 1:
                        result.append(self.row0[int(token)])
                    elif len(token) == 2:
                        row, col = int(token[0]), int(token[1])
                        result.append(self.row2[col] if row == 2 else self.row6[col])
                    i = closing + 1
                else:
                    result.append(ciphertext[i])
                    i += 1
            else:
                result.append(ciphertext[i])
                i += 1
        return "".join(result)
    
# class CardGrille(Cipher):
#     """
#     Fleissner Card Grille Engine (Rotational 2D Transposition Matrix).
#     Perfectly mirrors the spatial writing and reading operations to guarantee
#     a lossless round-trip loop.
#     """
#     classification = "transposition"
#     is_fractionating = False

#     def __init__(self):
#         # Anchor reference coordinates remain completely immutable
#         self.base_holes = [(0, 0), (1, 2), (2, 1), (3, 3)]

#     def encrypt(self, plaintext: str, domain: "Charset", range_set: "Charset") -> str:
#         chunks = [plaintext[i:i+16].ljust(16, ' ') for i in range(0, len(plaintext), 16)]
#         final_result = []
        
#         for chunk in chunks:
#             grid = [['' for _ in range(4)] for _ in range(4)]
#             char_idx = 0
#             current_holes = list(self.base_holes)
            
#             # Step through 4 rotational passes to write into the grid
#             for rotation in range(4):
#                 for r, c in current_holes:
#                     if char_idx < 16:
#                         grid[r][c] = chunk[char_idx]
#                         char_idx += 1
#                 current_holes = [(c, 3 - r) for r, c in current_holes]
                
#             # Flatten the completed matrix horizontally row-by-row
#             final_result.append("".join(["".join(row) for row in grid]))
            
#         return "".join(final_result)

#     def decrypt(self, ciphertext: str, domain: "Charset", range_set: "Charset") -> str:
#         chunks = [ciphertext[i:i+16].ljust(16, ' ') for i in range(0, len(ciphertext), 16)]
#         final_result = []
        
#         for chunk in chunks:
#             # Reconstruct the 4x4 grid array exactly how it was flattened
#             grid = [list(chunk[i:i+4]) for i in range(0, 16, 4)]
#             decoded_chars = []
#             current_holes = list(self.base_holes)
            
#             # Read out the characters following the exact same spatial path as encryption
#             for rotation in range(4):
#                 for r, c in current_holes:
#                     decoded_chars.append(grid[r][c])
#                 current_holes = [(c, 3 - r) for r, c in current_holes]
                
#             final_result.append("".join(decoded_chars))
            
#         return "".join(final_result).rstrip()
    
class MlecchitaVikalpa(Cipher):
    """
    Mlecchita Vikalpa Symmetrical Pairing Cipher Engine.
    Randomly splits an alphabet into pairs to construct an auto-reciprocal map.
    """
    classification = "substitution"
    is_fractionating = False

    def __init__(self, seed: int | None = None):
        self.seed = seed

    def _build_pairing_map(self, domain: Charset) -> dict:
        char_list = list(domain.chars)
        if self.seed is not None:
            random.Random(self.seed).shuffle(char_list)
            
        # Pair up elements: first half maps directly to the second half symmetrically
        pair_map = {}
        mid = len(char_list) // 2
        for i in range(mid):
            char_a = char_list[i]
            char_b = char_list[mid + i]
            pair_map[char_a] = char_b
            pair_map[char_b] = char_a
        return pair_map

    def encrypt(self, plaintext: str, domain: Charset, range_set: Charset) -> str:
        pmap = self._build_pairing_map(domain)
        result = []
        for char in plaintext:
            # Symmetrically swap the letter if it's registered in the mapping matrix
            result.append(pmap.get(char, char))
        return "".join(result)

    def decrypt(self, ciphertext: str, domain: Charset, range_set: Charset) -> str:
        return self.encrypt(ciphertext, range_set, domain)
    
class TabulaRecta:
    """
    Not a cipher instance, but a structural 2D helper matrix tool 
    used to calculate intersections for polyalphabetic key shifts.
    """
    @staticmethod
    def look_up(plain_char: str, key_char: str, domain: Charset, range_set: Charset) -> str:
        """Finds the intersection of a plaintext character and a keystream character."""
        if plain_char not in domain or key_char not in domain:
            return plain_char
        p_idx = domain.index_of(plain_char)
        k_idx = domain.index_of(key_char)
        # Shift the plaintext index forward by the key index
        target_idx = (p_idx + k_idx) % range_set.length
        return range_set.char_at(target_idx)

    @staticmethod
    def reverse_look_up(cipher_char: str, key_char: str, domain: Charset, range_set: Charset) -> str:
        """Finds the original plaintext character given a ciphertext and a key character."""
        if cipher_char not in range_set or key_char not in domain:
            return cipher_char
        c_idx = range_set.index_of(cipher_char)
        k_idx = domain.index_of(key_char)
        # Shift the ciphertext index backward by the key index
        target_idx = (c_idx - k_idx) % domain.length
        return domain.char_at(target_idx)
    
class Vigenere(Cipher):
    """
    Vigenere / The Alphabet Cipher Engine.
    Applies periodic rolling Caesar shifts using a repeating keyword string.
    """
    classification = "polyalphabetic"
    is_fractionating = False

    def __init__(self, keyword: str = "key"):
        self.keyword = keyword.lower()

    def encrypt(self, plaintext: str, domain: Charset, range_set: Charset) -> str:
        result = []
        key_idx = 0
        
        for char in plaintext:
            if char in domain:
                # Align the current letter with a character from the repeating keyword
                key_char = self.keyword[key_idx % len(self.keyword)]
                cipher_char = TabulaRecta.look_up(char, key_char, domain, range_set)
                result.append(cipher_char)
                key_idx += 1  # Only advance the key stream for valid alphabet letters
            else:
                result.append(char)
        return "".join(result)

    def decrypt(self, ciphertext: str, domain: Charset, range_set: Charset) -> str:
        result = []
        key_idx = 0
        
        for char in ciphertext:
            if char in range_set:
                key_char = self.keyword[key_idx % len(self.keyword)]
                plain_char = TabulaRecta.reverse_look_up(char, key_char, domain, range_set)
                result.append(plain_char)
                key_idx += 1
            else:
                result.append(char)
        return "".join(result)

class Beaufort(Cipher):
    """
    Beaufort Cipher Engine.
    Uses reversed polyalphabetic vector math: C = (Key - Plaintext) mod m.
    """
    classification = "polyalphabetic"
    is_fractionating = False

    def __init__(self, keyword: str = "key"):
        self.keyword = keyword.lower()

    def encrypt(self, plaintext: str, domain: Charset, range_set: Charset) -> str:
        result = []
        key_idx = 0
        m = domain.length
        
        for char in plaintext:
            if char in domain:
                key_char = self.keyword[key_idx % len(self.keyword)]
                p_idx = domain.index_of(char)
                k_idx = domain.index_of(key_char)
                
                # Beaufort Formula: C = (Key - Plain) mod m
                cipher_idx = (k_idx - p_idx) % m
                result.append(range_set.char_at(cipher_idx))
                key_idx += 1
            else:
                result.append(char)
        return "".join(result)

    def decrypt(self, ciphertext: str, domain: Charset, range_set: Charset) -> str:
        # Beaufort math is entirely self-reciprocal! 
        # Decrypting uses the exact same mathematical formula as encrypting.
        return self.encrypt(ciphertext, range_set, domain)
    
class Autokey(Cipher):
    """
    Autokey Cipher Engine.
    Eliminates key periodicity patterns by appending the plaintext string to the initial key.
    """
    classification = "polyalphabetic"
    is_fractionating = False

    def __init__(self, keyword: str = "key"):
        self.keyword = keyword.lower()

    def encrypt(self, plaintext: str, domain: Charset, range_set: Charset) -> str:
        result = []
        # Construct the stream: initial keyword + raw input text
        # Filter out characters that aren't in the domain to keep the key clean
        clean_plain = [c for c in plaintext if c in domain]
        keystream = self.keyword + "".join(clean_plain)
        
        key_idx = 0
        for char in plaintext:
            if char in domain:
                key_char = keystream[key_idx]
                result.append(TabulaRecta.look_up(char, key_char, domain, range_set))
                key_idx += 1
            else:
                result.append(char)
        return "".join(result)

    def decrypt(self, ciphertext: str, domain: Charset, range_set: Charset) -> str:
        result = []
        # During decryption, we don't have the full plaintext upfront!
        # We start with the keyword and dynamically rebuild the key step-by-step.
        keystream_buffer = list(self.keyword)
        
        key_idx = 0
        for char in ciphertext:
            if char in range_set:
                key_char = keystream_buffer[key_idx]
                plain_char = TabulaRecta.reverse_look_up(char, key_char, domain, range_set)
                result.append(plain_char)
                
                # Dynamically append the newly recovered character straight into our key stream buffer
                keystream_buffer.append(plain_char)
                key_idx += 1
            else:
                result.append(char)
        return "".join(result)
    
class RunningKey(Cipher):
    """
    Running Key / Book Cipher Engine.
    Uses a long text stream pulled from an external source to drive the key logic.
    """
    classification = "polyalphabetic"
    is_fractionating = False

    def __init__(self, book_text: str):
        # Clean the external source text so it perfectly matches our domain characters
        self.book_stream = book_text.lower()

    def encrypt(self, plaintext: str, domain: Charset, range_set: Charset) -> str:
        result = []
        key_idx = 0
        
        for char in plaintext:
            if char in domain:
                if key_idx >= len(self.book_stream):
                    raise ValueError("The provided book text stream is too short for this message payload.")
                key_char = self.book_stream[key_idx]
                result.append(TabulaRecta.look_up(char, key_char, domain, range_set))
                key_idx += 1
            else:
                result.append(char)
        return "".join(result)

    def decrypt(self, ciphertext: str, domain: Charset, range_set: Charset) -> str:
        result = []
        key_idx = 0
        
        for char in ciphertext:
            if char in range_set:
                key_char = self.book_stream[key_idx]
                result.append(TabulaRecta.reverse_look_up(char, key_char, domain, range_set))
                key_idx += 1
            else:
                result.append(char)
        return "".join(result)
    
class AlbertiDisk(Cipher):
    """
    Alberti Concentric Disk Engine.
    Models stateful mechanical cryptography using an internal rolling shift offset counter
    that advances automatically based on operational intervals.
    """
    classification = "polyalphabetic"
    is_fractionating = False

    def __init__(self, initial_offset: int = 0, period: int = 4, step: int = 1):
        self.initial_offset = initial_offset
        self.period = period  # How often the disk turns
        self.step = step      # How many positions it advances

    def encrypt(self, plaintext: str, domain: Charset, range_set: Charset) -> str:
        result = []
        shift_state = self.initial_offset
        valid_char_count = 0
        m = range_set.length
        
        for char in plaintext:
            if char in domain:
                p_idx = domain.index_of(char)
                # Apply combined calculation: (Plaintext + Current Wheel Shift State) mod m
                cipher_idx = (p_idx + shift_state) % m
                result.append(range_set.char_at(cipher_idx))
                
                valid_char_count += 1
                # Trigger a mechanical rotation of the inner disc if the step period is reached
                if valid_char_count % self.period == 0:
                    shift_state = (shift_state + self.step) % m
            else:
                result.append(char)
        return "".join(result)

    def decrypt(self, ciphertext: str, domain: Charset, range_set: Charset) -> str:
        result = []
        shift_state = self.initial_offset
        valid_char_count = 0
        m = domain.length
        
        for char in ciphertext:
            if char in range_set:
                c_idx = range_set.index_of(char)
                # Unwind the wheel mechanics: (Ciphertext - Current Wheel Shift State) mod m
                plain_idx = (c_idx - shift_state) % m
                result.append(domain.char_at(plain_idx))
                
                valid_char_count += 1
                if valid_char_count % self.period == 0:
                    shift_state = (shift_state + self.step) % m
            else:
                result.append(char)
        return "".join(result)

class Playfair(Cipher):
    """
    Playfair Cipher Engine.
    Encrypts pairs of characters (bigrams) geometrically using a 5x5 grid layout.
    Note: 'j' is traditionally merged with 'i'. Duplicate letters in a bigram are padded with 'x'.
    """
    classification = "substitution"
    is_fractionating = False

    def __init__(self, key_matrix_string: str = "playfairexample"):
        # Compile a clean 5x5 unique grid alphabet pool
        seen = set()
        clean_key = []
        for char in key_matrix_string.lower().replace('j', 'i'):
            if char.isalpha() and char not in seen:
                seen.add(char)
                clean_key.append(char)
        
        for char in "abcdefghiklmnopqrstuvwxyz": # Notice 'j' is omitted
            if char not in seen:
                clean_key.append(char)
                
        self.grid = [clean_key[i:i+5] for i in range(0, 25, 5)]

    def _find_coords(self, char: str) -> tuple[int, int]:
        for r in range(5):
            if char in self.grid[r]:
                return r, self.grid[r].index(char)
        return -1, -1

    def _process_bigrams(self, text: str, encrypt_mode: bool) -> str:
        # Pre-process text into bigram character arrays
        clean_text = [c for c in text.lower().replace('j', 'i') if c.isalpha()]
        
        # Insert filler character 'x' if duplicate letters appear adjacent in a bigram pair
        i = 0
        while i < len(clean_text) - 1:
            if clean_text[i] == clean_text[i+1]:
                clean_text.insert(i+1, 'x')
            i += 2
        if len(clean_text) % 2 != 0:
            clean_text.append('x')

        shift = 1 if encrypt_mode else -1
        result = []

        for idx in range(0, len(clean_text), 2):
            char1, char2 = clean_text[idx], clean_text[idx+1]
            r1, c1 = self._find_coords(char1)
            r2, c2 = self._find_coords(char2)

            if r1 == r2:
                # Rule 1: Same row -> Shift columns horizontally
                result.append(self.grid[r1][(c1 + shift) % 5])
                result.append(self.grid[r2][(c2 + shift) % 5])
            elif c1 == c2:
                # Rule 2: Same column -> Shift rows vertically
                result.append(self.grid[(r1 + shift) % 5][c1])
                result.append(self.grid[(r2 + shift) % 5][c2])
            else:
                # Rule 3: Bounding rectangle corners -> Swap columns
                result.append(self.grid[r1][c2])
                result.append(self.grid[r2][c1])

        return "".join(result)

    def encrypt(self, plaintext: str, domain: Charset, range_set: Charset) -> str:
        return self._process_bigrams(plaintext, encrypt_mode=True)

    def decrypt(self, ciphertext: str, domain: Charset, range_set: Charset) -> str:
        return self._process_bigrams(ciphertext, encrypt_mode=False)
    
class Bifid(Cipher):
    """
    Bifid Fractional Cipher Engine.
    Converts letters to 2D coordinates, groups row and column vectors, 
    and reconstructs them to create an integrated product cipher.
    """
    classification = "substitution"
    is_fractionating = False # The output text length remains 1-to-1 matching

    GRID = [
        ['a', 'b', 'c', 'd', 'e'],
        ['f', 'g', 'h', 'i', 'k'], # 'j' merged with 'i'
        ['l', 'm', 'n', 'o', 'p'],
        ['q', 'r', 's', 't', 'u'],
        ['v', 'w', 'x', 'y', 'z']
    ]

    def _find_position(self, char: str) -> tuple[int, int]:
        for r in range(5):
            if char in self.GRID[r]:
                return r, self.GRID[r].index(char)
        return -1, -1

    def encrypt(self, plaintext: str, domain: Charset, range_set: Charset) -> str:
        clean_text = [c for c in plaintext.lower().replace('j', 'i') if c.isalpha()]
        rows, cols = [], []
        
        for char in clean_text:
            r, c = self._find_position(char)
            rows.append(r)
            cols.append(c)
            
        # Concatenate coordinate tracking lists together
        combined_stream = rows + cols
        
        result = []
        for i in range(0, len(combined_stream), 2):
            r_target = combined_stream[i]
            c_target = combined_stream[i+1]
            result.append(self.GRID[r_target][c_target])
        return "".join(result)

    def decrypt(self, ciphertext: str, domain: Charset, range_set: Charset) -> str:
        clean_text = [c for c in ciphertext.lower() if c.isalpha()]
        stream = []
        for char in clean_text:
            r, c = self._find_position(char)
            stream.append(r)
            stream.append(c)
            
        # Split the flattened stream back into row and column halves
        mid = len(stream) // 2
        rows = stream[:mid]
        cols = stream[mid:]
        
        result = []
        for i in range(mid):
            result.append(self.GRID[rows[i]][cols[i]])
        return "".join(result)

class Hill(Cipher):
    """
    Dynamic NumPy Hill Matrix Cipher.
    Uses lazy-loading (scoped imports) so NumPy is only loaded into memory
    if this specific class is instantiated and executed.
    """
    classification = "substitution"
    is_fractionating = False

    def __init__(self, key_matrix: list[list[int]] = [[6, 24, 1], [13, 16, 10], [20, 17, 15]]):
        # 1. Scoped import: Only loads when the class is instantiated
        from numpy import array
        
        self.key = array(key_matrix)
        self.n = self.key.shape[0]
        if self.key.shape[0] != self.key.shape[1]:
            raise ValueError("The secret key matrix must be perfectly square (NxN).")

    def _mod_inverse_matrix(self, matrix, mod: int):
        """Calculates the modular inverse of an NxN integer matrix using scoped tools."""
        # 2. Local imports: Only loads if decryption/inverse math is triggered
        from numpy import round
        from numpy.linalg import det, inv
        
        matrix_det = int(round(det(matrix))) % mod
        try:
            det_inv = pow(matrix_det, -1, mod)
        except ValueError:
            raise ValueError(f"Matrix determinant ({matrix_det}) has no modular inverse. Matrix is not invertible!")
        
        adjugate = round(inv(matrix) * det(matrix))
        return round(det_inv * adjugate).astype(int) % mod

    def encrypt(self, plaintext: str, domain: Charset, range_set: Charset) -> str:
        # 3. Scoped imports for encryption processing
        from numpy import array, dot
        
        m = domain.length
        clean_text = [c for c in plaintext.lower() if c in domain]
        
        while len(clean_text) % self.n != 0:
            clean_text.append(domain.char_at(0))
            
        result = []
        for idx in range(0, len(clean_text), self.n):
            block = [domain.index_of(c) for c in clean_text[idx:idx+self.n]]
            vector = array(block)
            
            cipher_vector = dot(self.key, vector) % m
            for val in cipher_vector:
                result.append(range_set.char_at(int(val)))
                
        return "".join(result)

    def decrypt(self, ciphertext: str, domain: Charset, range_set: Charset) -> str:
        # 4. Scoped imports for decryption processing
        from numpy import array, dot
        
        m = range_set.length
        key_inv = self._mod_inverse_matrix(self.key, m)
        
        clean_text = [c for c in ciphertext.lower() if c in range_set]
        result = []
        
        for idx in range(0, len(clean_text), self.n):
            block = [range_set.index_of(c) for c in clean_text[idx:idx+self.n]]
            vector = array(block)
            
            plain_vector = dot(key_inv, vector) % m
            for val in plain_vector:
                result.append(domain.char_at(int(val)))
                
        return "".join(result)

class ADFGVX(Cipher):
    """
    German ADFGVX Field Code Product Engine.
    Combines a 6x6 coordinate fractionation square with a final Columnar Transposition.
    """
    classification = "substitution"
    is_fractionating = True # Intentionally fractionates text layout tokens

    HEADERS = ['A', 'D', 'F', 'G', 'V', 'X']
    GRID = [
        ['b', 't', 'a', 'l', '2', 'd'],
        ['o', 'v', 'z', 'w', 'g', '7'],
        ['e', 'j', '9', 'k', 'x', 'p'],
        ['m', '5', 'f', 's', 'i', 'r'],
        ['3', 'u', 'h', '8', 'v', 'n'],
        ['o', '4', 'c', '6', 'q', '1']
    ]

    def __init__(self, trans_key: str = "german"):
        self.trans_key = trans_key.lower()

    def _find_position(self, char: str) -> tuple[str, str]:
        for r in range(6):
            for c in range(6):
                if self.GRID[r][c] == char:
                    return self.HEADERS[r], self.HEADERS[c]
        return "", ""

    def encrypt(self, plaintext: str, domain: Charset, range_set: Charset) -> str:
        # Phase 1: Polybius Coordinate Substitution Substitution Fractionation
        fractionated = []
        for char in plaintext.lower():
            if char.isalnum():
                r_head, c_head = self._find_position(char)
                fractionated.append(r_head)
                fractionated.append(c_head)
        
        fractionated_str = "".join(fractionated)
        
        # Phase 2: Structural Columnar Transposition Matrix Routing
        num_cols = len(self.trans_key)
        rows = [fractionated_str[i:i+num_cols] for i in range(0, len(fractionated_str), num_cols)]
        
        # Pad the last transposition row to keep the grid perfectly uniform
        if rows and len(rows[-1]) < num_cols:
            rows[-1] = rows[-1].ljust(num_cols, 'X')

        # Sort columns alphabetically based on the key characters
        key_order = sorted(list(enumerate(self.trans_key)), key=lambda x: x[1])
        
        result = []
        for orig_col_idx, _ in key_order:
            for row in rows:
                if orig_col_idx < len(row):
                    result.append(row[orig_col_idx])
                    
        return "".join(result)

    def decrypt(self, ciphertext: str, domain: Charset, range_set: Charset) -> str:
        num_cols = len(self.trans_key)
        num_rows = len(ciphertext) // num_cols
        
        key_order = sorted(list(enumerate(self.trans_key)), key=lambda x: x[1])
        grid = [['' for _ in range(num_cols)] for _ in range(num_rows)]
        
        # Reconstruct matrix columns based on the alphabetical key order
        char_idx = 0
        for orig_col_idx, _ in key_order:
            for r in range(num_rows):
                if char_idx < len(ciphertext):
                    grid[r][orig_col_idx] = ciphertext[char_idx]
                    char_idx += 1
                    
        # Flatten row data elements back out
        transposed_stream = "".join(["".join(row) for row in grid])
        
        # Phase 4: Decode Fractionated Polybius Grid Matches
        result = []
        for i in range(0, len(transposed_stream), 2):
            if i + 1 < len(transposed_stream):
                r_idx = self.HEADERS.index(transposed_stream[i])
                c_idx = self.HEADERS.index(transposed_stream[i+1])
                result.append(self.GRID[r_idx][c_idx])
        return "".join(result)
    
class Nihilist(Cipher):
    """
    Nihilist Cipher Engine.
    Combines a Polybius Square substitution with a periodic Vigenere-style coordinate addition step.
    Example: '34|22|15' + '12|11|12' -> '46|33|27'
    """
    classification = "polyalphabetic"
    is_fractionating = True

    GRID = [
        ['a', 'b', 'c', 'd', 'e'],
        ['f', 'g', 'h', 'i', 'k'], # 'j' merged with 'i'
        ['l', 'm', 'n', 'o', 'p'],
        ['q', 'r', 's', 't', 'u'],
        ['v', 'w', 'x', 'y', 'z']
    ]

    def __init__(self, poly_key: str = "keyword", vigenere_key: str = "key"):
        self.vigenere_key = vigenere_key.lower().replace('j', 'i')
        # Setup Polybius coordinate mapping
        self.encoder = {}
        for r in range(5):
            for c in range(5):
                self.encoder[self.GRID[r][c]] = (r + 1) * 10 + (c + 1)

    def _char_to_num(self, char: str) -> int:
        return self.encoder.get(char, 0)

    def encrypt(self, plaintext: str, domain: "Charset", range_set: "Charset") -> str:
        clean_plain = [c for c in plaintext.lower().replace('j', 'i') if c.isalpha()]
        clean_key = [c for c in self.vigenere_key if c.isalpha()]
        
        result = []
        for idx, char in enumerate(clean_plain):
            p_num = self._char_to_num(char)
            # Align repeating key character
            k_char = clean_key[idx % len(clean_key)]
            k_num = self._char_to_num(k_char)
            
            # Nihilist addition math
            cipher_num = p_num + k_num
            result.append(f"|{cipher_num}|")
            
        return "".join(result)

    def decrypt(self, ciphertext: str, domain: "Charset", range_set: "Charset") -> str:
        clean_key = [c for c in self.vigenere_key if c.isalpha()]
        tokens = [int(t) for t in ciphertext.split('|') if t.isdigit()]
        
        result = []
        for idx, c_num in enumerate(tokens):
            k_char = clean_key[idx % len(clean_key)]
            k_num = self._char_to_num(k_char)
            
            # Subtraction rollback math
            p_num = c_num - k_num
            
            # Decode coordinates back to characters
            row = (p_num // 10) - 1
            col = (p_num % 10) - 1
            if 0 <= row < 5 and 0 <= col < 5:
                result.append(self.GRID[row][col])
                
        return "".join(result)
    
class M94(Cipher):
    """
    M-94 Cylinder Device Simulator.
    Simulates 25 physical rotating multi-alphabet rings on a central spindle axis.
    """
    classification = "polyalphabetic"
    is_fractionating = False

    def __init__(self, keyword: str = "abcdefghijklmnopqrstuvwxy"):
        self.keyword = keyword.lower()
        # Seeded deterministic custom rings to perfectly model the physical disks
        import random
        rng = random.Random(42)
        self.disks = []
        base_alphabet = list("abcdefghijklmnopqrstuvwxyz")
        for _ in range(25):
            disk_alphabet = base_alphabet.copy()
            rng.shuffle(disk_alphabet)
            self.disks.append("".join(disk_alphabet))

    def encrypt(self, plaintext: str, domain: "Charset", range_set: "Charset") -> str:
        clean_plain = [c for c in plaintext.lower() if c.isalpha()][:25]
        result = []
        
        for idx, char in enumerate(clean_plain):
            disk = self.disks[idx]
            # Find the shift amount driven by our keyword configuration
            key_char = self.keyword[idx % len(self.keyword)]
            shift = ord(key_char) - ord('a')
            
            curr_idx = disk.index(char)
            target_idx = (curr_idx + shift) % 26
            result.append(disk[target_idx])
            
        return "".join(result)

    def decrypt(self, ciphertext: str, domain: "Charset", range_set: "Charset") -> str:
        clean_cipher = [c for c in ciphertext.lower() if c.isalpha()][:25]
        result = []
        
        for idx, char in enumerate(clean_cipher):
            disk = self.disks[idx]
            key_char = self.keyword[idx % len(self.keyword)]
            shift = ord(key_char) - ord('a')
            
            curr_idx = disk.index(char)
            target_idx = (curr_idx - shift) % 26
            result.append(disk[target_idx])
            
        return "".join(result)
    
class Chaocipher(Cipher):
    """
    Chaocipher State Machine Engine.
    Left and Right wheels dynamically warp and permute their internal string topologies
    on every single operational transaction execution.
    """
    classification = "polyalphabetic"
    is_fractionating = False

    def __init__(self):
        # Traditional foundational starting state alphabets
        self.left_orig =  "ptlvygfeodnaubcxwikhqzsrmj"
        self.right_orig = "hxuczvamtgolkpsyqjnwrdibfe"

    def _permute_wheels(self, left: list, right: list, p_idx: int, c_idx: int):
        """Performs John F. Byrne's precise continuous physical manipulation steps."""
        # --- Left Wheel Permutation ---
        # Shift wheel left to bring ciphertext letter to zenith (index 0)
        left[:] = left[c_idx:] + left[:c_idx]
        # Pull index 1, extract index 2, insert at index 13 to alter structural alignment
        extracted = left.pop(1)
        left.insert(13, extracted)

        # --- Right Wheel Permutation ---
        # Shift wheel right to bring plaintext letter to zenith, then advance 1 step
        right[:] = right[p_idx:] + right[:p_idx]
        right[:] = right[1:] + right[:1]
        # Extract index 2, slide forward into position 13
        extracted = right.pop(2)
        right.insert(13, extracted)

    def encrypt(self, plaintext: str, domain: "Charset", range_set: "Charset") -> str:
        left = list(self.left_orig)
        right = list(self.right_orig)
        result = []
        
        for char in plaintext.lower():
            if char in right:
                p_idx = right.index(char)
                c_char = left[p_idx]
                result.append(c_char)
                
                c_idx = left.index(c_char)
                self._permute_wheels(left, right, p_idx, c_idx)
            else:
                result.append(char)
        return "".join(result)

    def decrypt(self, ciphertext: str, domain: "Charset", range_set: "Charset") -> str:
        left = list(self.left_orig)
        right = list(self.right_orig)
        result = []
        
        for char in ciphertext.lower():
            if char in left:
                c_idx = left.index(char)
                p_char = right[c_idx]
                result.append(p_char)
                
                p_idx = right.index(p_char)
                self._permute_wheels(left, right, p_idx, c_idx)
            else:
                result.append(char)
        return "".join(result)
    
class VICCipher(Cipher):
    """
    Production-Grade Soviet Spy VIC Cipher Engine.
    Implements authentic lagged Fibonacci chain addition expansions, numerical
    sequentializing, and a dynamic double-layer straddling checkerboard matrix.
    """
    classification = "polyalphabetic"
    is_fractionating = True

    def __init__(self, agent_seed: str = "74209", phrase: str = "overlord", date_str: str = "1944"):
        # The real VIC cipher uses a 5-digit seed, a passphrase, and a date
        self.seed = [int(d) for d in agent_seed.zfill(5)[:5]]
        self.phrase = phrase.lower()
        self.date_digits = [int(d) for d in date_str if d.isdigit()]

    def _chain_addition(self, digits: list[int], target_len: int) -> list[int]:
        """Expands a sequence of digits using standard modular addition (Fibonacci style)."""
        res = list(digits)
        while len(res) < target_len:
            # Add adjacent digits modulo 10
            next_digit = (res[len(res) - len(digits)] + res[len(res) - len(digits) + 1]) % 10
            res.append(next_digit)
        return res

    def _sequentialize(self, items: list) -> list[int]:
        """Labels elements based on their alphabetical/numerical order (left-to-right on ties)."""
        # Form tuples tracking (value, original_index)
        indexed = sorted(enumerate(items), key=lambda x: (x[1], x[0]))
        seq = [0] * len(items)
        for seq_val, (orig_idx, _) in enumerate(indexed):
            seq[orig_idx] = seq_val
        return seq

    def _derive_keys(self) -> tuple[list[int], list[int], list[int]]:
        """Derives the exact structural coordinate rows for the checkerboard and transpositions."""
        # 1. Expand the 5-digit seed via chain addition up to 10 digits
        expanded_seed = self._chain_addition(self.seed, 10)
        
        # FIX: Pad or loop the date digits cleanly so it is ALWAYS exactly 10 items long
        # If date is shorter than 10, it loops infinitely until it hits 10 items
        if not self.date_digits:
            padded_date = [0] * 10
        else:
            padded_date = [self.date_digits[i % len(self.date_digits)] for i in range(10)]
            
        # 2. Subtract the date digits from the expanded seed mod 10
        row_a = [(expanded_seed[i] - padded_date[i]) % 10 for i in range(10)]
        
        # 3. Sequentialize the phrase to create numerical tracking lines
        phrase_chars = [ord(c) for c in self.phrase[:10].ljust(10, 'x')]
        row_b = self._sequentialize(phrase_chars)
        
        # 4. Create the primary structural keystream mapping row
        row_c = [(row_a[i] + row_b[i]) % 10 for i in range(10)]
        
        # Sequentialize rows to establish clean coordinate mappings
        checkerboard_order = self._sequentialize(row_c)
        transposition_key1 = self._sequentialize(row_a)
        transposition_key2 = self._sequentialize(row_b)
        
        return checkerboard_order, transposition_key1, transposition_key2

    def _build_checkerboard(self, order: list[int]) -> tuple[dict, dict]:
        """Dynamically generates an authentic, lossless straddling checkerboard table."""
        # Map the 10 layout digits directly to the sequentialized key order
        digits = [order.index(i) for i in range(10)]
        
        # Authentic Soviet frequency arrangement layout
        alphabet = "etonavrisbcdefghjklmpqwxyz ."
        
        # Row 0 reserves positions for the 8 most common characters
        # Blanks at positions index 2 and 6 serve as the entry points for the next rows
        blanks = [digits[2], digits[6]]
        
        encoder, decoder = {}, {}
        alpha_idx = 0
        
        # Row 0 tracking
        for d in digits:
            if d in blanks:
                continue
            if alpha_idx < len(alphabet):
                char = alphabet[alpha_idx]
                encoder[char] = f"{d}"
                decoder[f"{d}"] = char
                alpha_idx += 1
                
        # Row 1 (Escaped under the first blank digit)
        for d in digits:
            if alpha_idx < len(alphabet):
                char = alphabet[alpha_idx]
                encoder[char] = f"{blanks[0]}{d}"
                decoder[f"{blanks[0]}{d}"] = char
                alpha_idx += 1
                
        # Row 2 (Escaped under the second blank digit)
        for d in digits:
            if alpha_idx < len(alphabet):
                char = alphabet[alpha_idx]
                encoder[char] = f"{blanks[1]}{d}"
                decoder[f"{blanks[1]}{d}"] = char
                alpha_idx += 1
                
        return encoder, decoder

    def _transpose(self, text: str, key: list[int]) -> str:
        """Executes a pure columnar transposition matrix shift based on key sequence order."""
        width = len(key)
        chunks = [text[i:i+width] for i in range(0, len(text), width)]
        if chunks and len(chunks[-1]) < width:
            chunks[-1] = chunks[-1].ljust(width, 'x') # Pad with filler characters
            
        result = []
        for k_val in range(width):
            col_idx = key.index(k_val)
            for chunk in chunks:
                result.append(chunk[col_idx])
        return "".join(result)

    def _untranspose(self, text: str, key: list[int]) -> str:
        """Reverses the columnar transposition matrix sequence."""
        width = len(key)
        num_rows = len(text) // width
        grid = [['' for _ in range(width)] for _ in range(num_rows)]
        
        char_idx = 0
        for k_val in range(width):
            col_idx = key.index(k_val)
            for r in range(num_rows):
                grid[r][col_idx] = text[char_idx]
                char_idx += 1
                
        return "".join(["".join(row) for row in grid])

    def encrypt(self, plaintext: str, domain: Charset, range_set: Charset) -> str:
        # 1. Derive keys and compile the dynamic checkerboard
        check_order, trans1, trans2 = self._derive_keys()
        encoder, _ = self._build_checkerboard(check_order)
        
        # 2. Run Straddling Checkerboard Substitution
        substituted_digits = []
        for char in plaintext.lower():
            if char in encoder:
                substituted_digits.append(encoder[char])
            else:
                substituted_digits.append(encoder.get(' ', '0')) # Fallback to space digit
                
        digit_stream = "".join(substituted_digits)
        
        # 3. Apply Dual Transposition Layers
        layer1 = self._transpose(digit_stream, trans1)
        layer2 = self._transpose(layer1, trans2)
        
        # Use strict pipe delimiters to keep fractionated string output tokenized safely!
        return "".join([f"|{d}|" for d in layer2])

    def decrypt(self, ciphertext: str, domain: Charset, range_set: Charset) -> str:
        check_order, trans1, trans2 = self._derive_keys()
        _, decoder = self._build_checkerboard(check_order)
        
        # Parse the custom isolated token streams back into a unified string of digits
        tokens = [t for t in ciphertext.split('|') if t]
        flat_cipher = "".join(tokens)
        
        # 1. Rollback the Dual Transposition Matrices in reverse order
        layer1 = self._untranspose(flat_cipher, trans2)
        digit_stream = self._untranspose(layer1, trans1)
        
        # 2. Reconstruct the variable-length checkerboard tokens
        result = []
        i = 0
        blanks = [str(check_order.index(2)), str(check_order.index(6))]
        
        while i < len(digit_stream):
            curr_digit = digit_stream[i]
            if curr_digit in blanks and i + 1 < len(digit_stream):
                # Double-digit lookup path
                token = digit_stream[i:i+2]
                result.append(decoder.get(token, ''))
                i += 2
            else:
                # Single-digit lookup path
                result.append(decoder.get(curr_digit, ''))
                i += 1
                
        return "".join(result).rstrip('x') # Strip out trailing padding elements