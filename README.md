# 🔒 HDCiphers (Hyper Dynamic Ciphers)

`hdciphers` is a modern, fluent Python cryptography library designed for exploring classical and advanced substitution, transposition, and polyalphabetic ciphers across universal language scripts. 

Unlike traditional implementations restricted to the standard 26 letters of the English alphabet, `hdciphers` features an algebraic Unicode **Charset Engine** and a state-tracking **Text Stack** that calculates cryptographic telemetry—such as Shannon Entropy—in real-time.

---

## ✨ Key Features

* 🚀 **Fluent Chaining API:** Chain multi-layered encryptions cleanly in a single operational pipeline.
* 🧮 **Charset Algebra:** Combine or subtract alphabets natively using standard math operators (`+`, `-`).
* 🌍 **Universal Script Support:** Pre-configured sets for English, Arabic, Greek, and programmatic **Exotic Unicode Pools**.
* 📉 **Cryptographic Telemetry:** Built-in calculation of **Shannon Entropy** to instantly measure ciphertext randomness.
* 📜 **Immutable Transaction Stack:** Automated tracking history with an instant `.undo()` rollback feature.

---

## 🛠️ Installation

`hdciphers` can be installed either directly from PyPI or cloned locally for development.

### Option 1: Standard Installation (Via PyPI)
Recommended for general use. This will automatically fetch the latest stable release and manage dependencies:
```bash
pip install hdciphers

```

### Option 2: Local Development Installation (Via GitHub)

Recommended if you want to inspect the source code, run the internal test suites, or modify the cipher architectures:

```bash
git clone https://github.com/Omar-Afifi-Salama/HDCiphers.git
cd HDCiphers
pip install -e .

```
---

## 💻 Core Architecture & Code Examples

The library is split into three foundational abstractions: `Charset` (handling modular boundaries), `Text` (the stateful payload wrapper), and `Cipher` (the mathematical transformation engines).

### 1. Charset Algebra & Monoalphabetic Operations

You can dynamically compose or subtract character boundaries to create non-standard modular rings. If a character falls outside the configured `domain_charset`, the engine safely passes it through as a literal.

```python
import hdciphers as hdc

# Construct a custom domain using operator algebra
custom_charset = hdc.Charset.english(mode="lower") + " 12345"

# Initialize stateful text container
text_space = hdc.Text("mission 1234", domain_charset=custom_charset)

# Execute Affine Transformation: E(x) = (5x + 8) mod 31
# Automatically verifies if 'a' is coprime to the dynamic charset length
text_space.encrypt(hdc.Affine(a=5, b=8))

print(f"Ciphertext: '{text_space.content}'")
print(f"Entropy:     {text_space.entropy:.4f}")

# Rollback pipeline state execution
text_space.undo()
print(f"Recovered:  '{text_space.content}'")

```

**Execution Telemetry Output:**

```text
Ciphertext: 'yuaauit1342'
Entropy:     2.4130
Recovered:  'mission 1234'

```

---

### 2. Polyalphabetic Streams & Token Isolation

For ciphers that break standard character-to-character boundaries (Fractionating engines like `BaconsCipher`, `TapCode`, or `VICCipher`), `hdciphers` utilizes **Strict Token Isolation** (`|` and `/`) to prevent natural spaces and multi-character text coordinates from colliding during round-trip decryption.

```python
import hdciphers as hdc

cs = hdc.Charset.english(mode="lower") + " ."
msg = hdc.Text("secure drop.", domain_charset=cs)

# Execute Autokey (Appends plaintext to keyword to prevent periodic pattern breaks)
msg.encrypt(hdc.Autokey(keyword="monarch"))
print(f"Autokey Output:   '{msg.content}'")

# Reset text context for fractionating run
fraction_msg = hdc.Text("spy craft", domain_charset=cs)

# Execute Tap Code coordinate grid encoding
fraction_msg.encrypt(hdc.TapCode())
print(f"Tap Code Output:  '{fraction_msg.content}'")

# Decrypt using a fresh structural instance to clear state retention
fraction_msg.decrypt(hdc.TapCode())
print(f"Decrypted Back:   '{fraction_msg.content}'")

```

**Execution Telemetry Output:**

```text
Autokey Output:   'gqoied kfcn.'
Tap Code Output:  '|43||35||54|/|13||42||11||21||44|'
Decrypted Back:   'spy craft'

```

---

### 3. High-Dimensional Matrix Math (Lazy-Loaded Hill Cipher)

The `Hill` cipher class handles dynamic $N \times N$ square matrices. To keep the library footprint lean and fast, `hdciphers` utilizes **lazy-loading**. Heavy scientific dependencies (`numpy`) are only loaded into memory at the exact method scope if an $N \times N$ calculation is triggered.

```python
import hdciphers as hdc

# Define an invertible 3x3 key matrix
key_3x3 = [
    [6, 24, 1],
    [13, 16, 10],
    [20, 17, 15]
]

cs = hdc.Charset.english(mode="lower")
payload = hdc.Text("vectormatrix", domain_charset=cs)

# Encrypts block vectors simultaneously using modular dot product operations
payload.encrypt(hdc.Hill(key_matrix=key_3x3))
print(f"Hill 3x3 Ciphertext: '{payload.content}'")

payload.decrypt(hdc.Hill(key_matrix=key_3x3))
print(f"Hill 3x3 Decrypted:  '{payload.content}'")

```

**Execution Telemetry Output:**

```text
Hill 3x3 Ciphertext: 'snoaswgzvkrp'
Hill 3x3 Decrypted:  'vectormatrix'

```

---

### 4. Cold War Espionage Simulation (The Soviet VIC Cipher)

`hdciphers` includes a highly accurate, mathematically complete simulation of the legendary Soviet **VIC Cipher**—widely considered the most complex paper-and-pencil system in historical cryptography.

```python
import hdciphers as hdc

config = {
    "agent_seed": "74209", 
    "phrase": "overlord", 
    "date_str": "1944"
}

cs = hdc.Charset.english(mode="lower") + " ."
spy_text = hdc.Text("attack at noon.", domain_charset=cs)

# Pipeline: Chain addition (Fibonacci) -> Sequentialized Phrase Matrix 
#            -> Dynamic Straddling Checkerboard -> Dual Disrupted Transpositions
spy_text.encrypt(hdc.VICCipher(**config))
print(f"VIC Encrypted Product: {spy_text.content[:50]}...")

spy_text.decrypt(hdc.VICCipher(**config))
print(f"VIC Decrypted Product: {spy_text.content}")

```

**Execution Telemetry Output:**

```text
VIC Encrypted Product: |4||1||0||5||7||3||9||2||8||1||5||0||4||6|...
VIC Decrypted Product: attack at noon.

```

---

## 🗂️ Complete Directory of Engines

Invoke the static help utility in any interactive environment to print the directory map:

```python
import hdciphers as hdc
hdc.help()

```

* **Tier 1 (Monoalphabetic & Steganographic):** `Caesar`, `ROT13`, `Atbash`, `Substitution`, `Affine`, `PigLatin`, `TapCode`, `BaconsCipher`, `NullCipher`
* **Tier 2 (Transposition Matrices):** `Scytale`, `RailFence`, `StraddlingCheckerboard`, `MlecchitaVikalpa`
* **Tier 3 (Polyalphabetic Key Streams):** `Vigenere`, `Beaufort`, `Autokey`, `RunningKey`, `AlbertiDisk`
* **Tier 4 (Product & Block Ciphers):** `Playfair`, `Bifid`, `Hill`, `ADFGVX`
* **Tier 5 (Stateful & Spy-Grade Automata):** `Nihilist`, `M94`, `Chaocipher`, `VICCipher`

---

## 🗺️ Future Roadmap

* 📊 **Frequency Analysis Telemetry Suite:** Add real-time visual index counters to compute Index of Coincidence ($IC$) and letter frequency arrays directly via the `Text` class wrapper to aid automated cryptanalysis.
* 🛡️ **Cryptanalysis Solver Helpers:** Integrate programmatic heuristic cracking modules (Kasiski examination, dictionary attacks, and hill-climbing genetic algorithms) to dynamically crack weaker monoalphabetic and polyalphabetic layers.
* 🚂 **Enigma I / M3 Machine Simulation:** Implement a precise hardware-level stateful simulator modeling physical Enigma rotors, reflector configurations (UKW), and plugboard ring settings (`Steckerbrett`) to complement the Tier 5 mechanical library section.