from .classes import Cipher, Charset

class Caesar(Cipher):

    classification = "substitution"

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