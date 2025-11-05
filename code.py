import secrets
import ecdsa
from sha3 import keccak_256  # pip install pysha3

def generate_ethereum_address():
    """
    Generate a random Ethereum address (checksummed format).
    
    Returns:
    tuple: (private_key_hex, public_key_hex, ethereum_address)
    """
    # Step 1: Generate a random private key (32 bytes)
    private_key = secrets.token_bytes(32)
    private_key_hex = private_key.hex()
    
    # Step 2: Derive the public key using ECDSA (secp256k1 curve, uncompressed)
    signing_key = ecdsa.SigningKey.from_string(private_key, curve=ecdsa.SECP256k1)
    verifying_key = signing_key.verifying_key
    public_key = b'\x04' + verifying_key.to_string()  # Uncompressed public key
    public_key_hex = public_key.hex()
    
    # Step 3: Keccak-256 hash of the public key (excluding the 0x04 prefix)
    k = keccak_256()
    k.update(public_key[1:])  # Remove the compression flag byte
    address_bytes = k.digest()[-20:]  # Last 20 bytes
    
    # Step 4: Convert to hex and add 0x prefix
    address_lower = '0x' + address_bytes.hex()
    
    # Step 5: Generate EIP-55 checksummed address
    addr_hash = keccak_256()
    addr_hash.update(address_lower[2:].encode('utf-8'))  # Hash the lowercase address without 0x
    addr_hash_hex = addr_hash.hexdigest()
    
    checksum_address = '0x'
    for i, char in enumerate(address_lower[2:]):
        if int(addr_hash_hex[i], 16) >= 8:
            checksum_address += char.upper()
        else:
            checksum_address += char.lower()
    
    return private_key_hex, public_key_hex, checksum_address

# Example usage
if __name__ == "__main__":
    priv_key, pub_key, address = generate_ethereum_address()
    print(f"Private Key (hex): {priv_key}")
    print(f"Public Key (hex): {pub_key}")
    print(f"Ethereum Address: {address}")