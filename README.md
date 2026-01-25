# Vanity Ed25519 Key Generator

High-performance parallel bruteforce tool for generating Ed25519 keypairs whose public key SHA256 hash matches a regex pattern.

## Performance

- **C++ version**: ~650,000 keys/s (12 threads)
- **Python version**: ~300,000 keys/s (12 threads)
- **web version**: ~5000 keys/s (no threads, webassembly)

## Files

| File | Description |
|------|-------------|
| `hashes_fast.cpp` | High-performance C++ implementation |
| `hashes_fast.exe` | Compiled executable (requires MSYS2 runtime) |
| `hashes_parallel.py` | Python multiprocessing version |
| `hashes.py` | Original single-threaded Python version |

---

## C++ Version (Fastest)

### Prerequisites

- [MSYS2](https://www.msys2.org/) with UCRT64 toolchain installed
- Or copy the required DLLs alongside the executable

### Building

```powershell
# In PowerShell, add MSYS2 to PATH first
$env:Path = "C:\msys64\ucrt64\bin;" + $env:Path

# Compile
g++ -O3 -march=native -mtune=native -std=c++17 -pthread -ffast-math -funroll-loops -flto -o hashes_fast.exe hashes_fast.cpp
```

### Running

**Important:** The executable requires MSYS2 runtime DLLs. Either:

#### Option 1: Add MSYS2 to PATH (recommended)
```powershell
$env:Path = "C:\msys64\ucrt64\bin;" + $env:Path
.\hashes_fast.exe "^00bfc00" 12
```

#### Option 2: Run from MSYS2 terminal
```bash
./hashes_fast.exe "^00bfc00" 12
```

#### Option 3: Copy DLLs (for portable use)
Copy these DLLs from `C:\msys64\ucrt64\bin\` to the same folder as the exe:
- `libgcc_s_seh-1.dll`
- `libstdc++-6.dll`
- `libwinpthread-1.dll`

### Usage

```
hashes_fast.exe <regex_pattern> [num_workers]
```

**Arguments:**
- `regex_pattern` - Regex to match against the SHA256 hash (hex string)
- `num_workers` - Number of parallel workers (default: CPU cores)

**Examples:**
```powershell
# Find hash starting with "bfc0"
.\hashes_fast.exe "^bfc0" 12

# Find hash starting with "00000" (harder, takes longer)
.\hashes_fast.exe "^00000" 12

# Find hash containing "dead"
.\hashes_fast.exe "dead" 12
```

---

## Python Version

### Prerequisites

```bash
pip install PyNaCl
```

### Running

```powershell
# Parallel version (faster)
python hashes_parallel.py

# Single-threaded version
python hashes.py
```

---

## Output Format

When a match is found:

```
============================================================
MATCH FOUND!
============================================================
Hash:        00bfc00...
Seed (hex):           <32 bytes - the random seed>
Private Key (hex):    <64 bytes - seed || public_key>
Private Key (base64): <base64 encoded 64-byte private key>
Public Key (hex):     <32 bytes>
Public Key (base64):  <base64 encoded 32-byte public key>
============================================================
```

### Key Format (Ed25519)

- **Seed**: 32 bytes (random)
- **Private Key**: 64 bytes = seed (32) + public_key (32)
- **Public Key**: 32 bytes (derived from seed via Ed25519)

The private key format is compatible with libsodium/PyNaCl.

---

## Difficulty Estimates

| Pattern | Hex Chars | Expected Attempts | Time @ 650k/s |
|---------|-----------|-------------------|---------------|
| `^a` | 1 | ~16 | instant |
| `^ab` | 2 | ~256 | instant |
| `^abc` | 3 | ~4,096 | instant |
| `^abcd` | 4 | ~65,536 | <1 sec |
| `^abcde` | 5 | ~1,048,576 | ~2 sec |
| `^abcdef` | 6 | ~16,777,216 | ~26 sec |
| `^abcdefg` | 7 | ~268,435,456 | ~7 min |
| `^00000` | 5 | ~1,048,576 | ~2 sec |
| `^000000` | 6 | ~16,777,216 | ~26 sec |
| `^0000000` | 7 | ~268,435,456 | ~7 min |
