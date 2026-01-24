import hashlib

# Constants for Ed25519 key sizes
CRYPTO_SIGN_ED25519_PUBLICKEYBYTES = 32
CRYPTO_SIGN_ED25519_SECRETKEYBYTES = 64

# Privacy levels
PUBLIC = "public"
PRIVATE = "private"


def base64_decode(string):
    # Allocate output bytes (3 bytes per 4 characters)
    bytes_data = bytearray((len(string) // 4) * 3)

    # Process each 4-character block
    for n in range(len(string) // 4):
        block = 0

        # Convert each of the 4 characters to 6-bit values and combine
        for i in range(4):
            ch = string[i + n * 4]

            # Map base64 character to 6-bit value
            if "A" <= ch <= "Z":
                val = ord(ch) - ord("A") + 0
            elif "a" <= ch <= "z":
                val = ord(ch) - ord("a") + 26
            elif "0" <= ch <= "9":
                val = ord(ch) - ord("0") + 52
            elif ch == "+":
                val = 62
            elif ch == "/":
                val = 63
            else:
                val = 0

            # Shift and OR into the 24-bit block
            block |= val << (6 * (3 - i))

        # Extract 3 bytes from the 24-bit block
        bytes_data[0 + n * 3] = (block >> 16) & 0xFF
        bytes_data[1 + n * 3] = (block >> 8) & 0xFF
        bytes_data[2 + n * 3] = block & 0xFF

    # Handle padding
    if len(string) >= 4:
        if string[(len(string) // 4) * 4 - 2] == "=":
            bytes_data = bytes_data[:-2]  # Remove 2 bytes
        elif string[(len(string) // 4) * 4 - 1] == "=":
            bytes_data = bytes_data[:-1]  # Remove 1 byte

    return bytes(bytes_data)


def base64_encode(data):
    """
    Encode bytes to base64 string.

    Args:
        data: bytes object to encode

    Returns:
        base64 encoded string
    """
    # Base64 alphabet
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

    result = []

    # Process each 3-byte block
    for n in range(len(data) // 3):
        # Combine 3 bytes into 24-bit block
        block = (data[n * 3] << 16) | (data[n * 3 + 1] << 8) | data[n * 3 + 2]

        # Extract 4 × 6-bit values and convert to base64 characters
        for i in range(4):
            val = (block >> (6 * (3 - i))) & 0x3F  # Extract 6 bits
            result.append(alphabet[val])

    # Handle remaining bytes (padding)
    remaining = len(data) % 3
    if remaining > 0:
        # Pad with zeros to make 3 bytes
        block = data[len(data) // 3 * 3] << 16
        if remaining == 2:
            block |= data[len(data) // 3 * 3 + 1] << 8

        # Extract the needed characters
        for i in range(remaining + 1):
            val = (block >> (6 * (3 - i))) & 0x3F
            result.append(alphabet[val])

        # Add padding '=' characters
        for i in range(3 - remaining):
            result.append("=")

    return "".join(result)


class EcKey:
    """Represents an EC key with public and private key bytes."""

    def __init__(self, public_key=None, private_key=None):
        self.public_key = public_key if public_key else b""
        self.private_key = private_key if private_key else b""

    def clear(self):
        """Clear both keys."""
        self.public_key = b""
        self.private_key = b""

    def empty(self):
        """Check if the key is empty."""
        return len(self.public_key) == 0

    def has_private(self):
        """Check if private key exists."""
        return len(self.private_key) == CRYPTO_SIGN_ED25519_SECRETKEYBYTES

    def to_bytes(self, privacy):
        """
        Extract key bytes based on privacy level.

        Args:
            privacy: PUBLIC or PRIVATE constant

        Returns:
            bytes object containing the requested key, or empty bytes on error
        """
        if self.empty():
            print("WARNING: No key")
            return b""

        # Verify public key size
        if len(self.public_key) != CRYPTO_SIGN_ED25519_PUBLICKEYBYTES:
            print(f"ERROR: Invalid public key size: {len(self.public_key)}")
            return b""

        if privacy == PUBLIC:
            return self.public_key
        elif privacy == PRIVATE:
            if len(self.private_key) != CRYPTO_SIGN_ED25519_SECRETKEYBYTES:
                print("ERROR: Failed to create external representation of private key")
                return b""
            return self.private_key
        else:
            print("FATAL: Unsupported privacy level")
            return b""

    def public_hash_string(self, truncate_to_length=0):
        """
        Returns the SHA256 hash of the public key.

        Args:
            truncate_to_length: optional length to truncate the hash string to

        Returns:
            SHA256 hash as hex string, possibly truncated
        """
        key_bytes = self.to_bytes(PUBLIC)
        if not key_bytes:
            return ""

        sha_str = hashlib.sha256(key_bytes).hexdigest()

        if truncate_to_length > 0 and truncate_to_length < len(sha_str):
            return sha_str[:truncate_to_length]

        return sha_str

    def public_key_hex_string(self, truncate_to_length=0):
        """
        Returns the public key, hex-encoded.

        Args:
            truncate_to_length: optional length to truncate the hex string to

        Returns:
            Hex-encoded public key, possibly truncated
        """
        key_bytes = self.to_bytes(PUBLIC)
        if not key_bytes:
            return ""

        hex_str = key_bytes.hex()

        if truncate_to_length > 0 and truncate_to_length < len(hex_str):
            return hex_str[:truncate_to_length]

        return hex_str


import re
import os
import time

try:
    from nacl.signing import SigningKey

    USE_NACL = True
except ImportError:
    USE_NACL = False
    print("Warning: PyNaCl not installed. Using fallback key generation.")
    print("Install with: pip install PyNaCl")


def generate_ed25519_keypair():
    """
    Generate an Ed25519 keypair using crypto_sign_ed25519_keypair.

    Returns:
        tuple: (public_key_bytes, private_key_bytes) - 32 bytes and 64 bytes respectively
    """
    if USE_NACL:
        # Use proper Ed25519 key generation via libsodium
        signing_key = SigningKey.generate()

        # In Ed25519, the private key is 64 bytes: 32-byte seed + 32-byte public key
        # signing_key._signing_key is the 32-byte seed
        # We need to construct the 64-byte private key format
        seed = bytes(signing_key)  # 32-byte seed
        public_key = bytes(signing_key.verify_key)  # 32-byte public key
        private_key = seed + public_key  # 64-byte private key (seed || public_key)

        return public_key, private_key
    else:
        # Fallback: Generate random seed and derive keys
        seed = os.urandom(32)
        # Simple derivation (not cryptographically proper Ed25519, but for demonstration)
        public_key = hashlib.sha256(seed).digest()[:32]
        private_key = seed + public_key
        return public_key, private_key


def bruteforce_key(regex_pattern, max_attempts=None):
    """
    Bruteforce private keys and find one whose public key hash matches the regex pattern.

    Args:
        regex_pattern: Regex pattern to match against the SHA256 hash (hex string)
        max_attempts: Maximum number of attempts (None for unlimited)

    Returns:
        Dictionary with 'private_key', 'public_key', and 'hash' if found, None otherwise
    """
    pattern = re.compile(regex_pattern)
    attempts = 0
    start_time = time.time()

    print(f"Starting bruteforce with pattern: {regex_pattern}")
    print(f"Using {'proper Ed25519' if USE_NACL else 'fallback'} key generation")
    print("Press Ctrl+C to stop\n")

    try:
        while max_attempts is None or attempts < max_attempts:
            # Generate Ed25519 keypair using crypto_sign_ed25519_keypair
            public_key, private_key = generate_ed25519_keypair()

            # Create EcKey and get hash
            ec_key = EcKey(public_key=public_key, private_key=private_key)
            hash_str = ec_key.public_hash_string()

            attempts += 1

            # Print every 100000 attempts
            if attempts % 100000 == 0:
                elapsed = time.time() - start_time
                rate = attempts / elapsed if elapsed > 0 else 0
                print(
                    f"Attempts: {attempts:,} | Rate: {rate:.0f}/s | Current hash: {hash_str[:16]}..."
                )

            # Check if hash matches pattern
            if pattern.search(hash_str):
                elapsed = time.time() - start_time
                print(f"\n✓ MATCH FOUND after {attempts:,} attempts in {elapsed:.2f}s!")
                print(f"Private key: {private_key.hex()}")
                print(f"Public key:  {public_key.hex()}")
                print(f"Hash:        {hash_str}")

                # Encode private key as base64 using our own function
                private_key_b64 = base64_encode(private_key)
                print(f"Private key (base64): {private_key_b64}")

                return {
                    "private_key": private_key,
                    "public_key": public_key,
                    "hash": hash_str,
                    "attempts": attempts,
                }

    except KeyboardInterrupt:
        elapsed = time.time() - start_time
        print(f"\n\nStopped after {attempts:,} attempts in {elapsed:.2f}s")
        return None

    print(f"\nNo match found after {max_attempts:,} attempts")
    return None


# Example usage:
# Find a hash that starts with "bfc0"
print("\n" + "=" * 60)
print("BRUTEFORCE VANITY KEY GENERATOR, version 2")
print("=" * 60)

# User input
regex_input = input(
    "Enter regex pattern for hash (e.g., '^bfc0' for starting with bfc0): "
).strip()
if not regex_input:
    regex_input = "^bfcbfc"  # Default pattern

max_attempts_input = input("Enter max attempts (press Enter for unlimited): ").strip()
max_attempts = int(max_attempts_input) if max_attempts_input else None

result = bruteforce_key(regex_input, max_attempts)
