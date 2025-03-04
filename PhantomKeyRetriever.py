import leveldb
import os
import shutil
import sys
import json
from hashlib import pbkdf2_hmac
from typing import Optional, Tuple, List, Union
import base58
import hashlib
from nacl.secret import SecretBox
from mnemonic import Mnemonic

# Scrypt encryption parameters
SCRYPT_N = 2 ** 12  # CPU/memory cost factor
SCRYPT_R = 8  # Block size parameter
SCRYPT_P = 1  # Parallelization parameter
SCRYPT_DKLEN = 32  # Length of the derived key

def print_banner():
    """Print the program banner and author information"""
    banner = """
██████╗ ██╗  ██╗ █████╗ ███╗   ██╗████████╗ ██████╗ ███╗   ███╗
██╔══██╗██║  ██║██╔══██╗████╗  ██║╚══██╔══╝██╔═══██╗████╗ ████║
██████╔╝███████║███████║██╔██╗ ██║   ██║   ██║   ██║██╔████╔██║
██╔═══╝ ██╔══██║██╔══██║██║╚██╗██║   ██║   ██║   ██║██║╚██╔╝██║
██║     ██║  ██║██║  ██║██║ ╚████║   ██║   ╚██████╔╝██║ ╚═╝ ██║
╚═╝     ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝   ╚═╝    ╚═════╝ ╚═╝     ╚═╝
██╗  ██╗███████╗██╗   ██╗    ██████╗ ███████╗████████╗██████╗ ██╗███████╗██╗   ██╗███████╗██████╗ 
██║ ██╔╝██╔════╝╚██╗ ██╔╝    ██╔══██╗██╔════╝╚══██╔══╝██╔══██╗██║██╔════╝██║   ██║██╔════╝██╔══██╗
█████╔╝ █████╗   ╚████╔╝     ██████╔╝█████╗     ██║   ██████╔╝██║█████╗  ██║   ██║█████╗  ██████╔╝
██╔═██╗ ██╔══╝    ╚██╔╝      ██╔══██╗██╔══╝     ██║   ██╔══██╗██║██╔══╝  ╚██╗ ██╔╝██╔══╝  ██╔══██╗
██║  ██╗███████╗   ██║       ██║  ██║███████╗   ██║   ██║  ██║██║███████╗ ╚████╔╝ ███████╗██║  ██║
╚═╝  ╚═╝╚══════╝   ╚═╝       ╚═╝  ╚═╝╚══════╝   ╚═╝   ╚═╝  ╚═╝╚═╝╚══════╝  ╚═══╝  ╚══════╝╚═╝  ╚═╝
                                                @SlowMist Team    
"""
    print(banner)

class KDFError(Exception):
    """Exception raised for KDF-related errors"""
    pass


def decode_bytes_to_string(data: bytes) -> str:
    """
    Attempt to decode byte data to UTF-8 string, fallback to hexadecimal representation

    Args:
        data: Bytes to decode

    Returns:
        Decoded string or hexadecimal representation if UTF-8 decode fails
    """
    try:
        return data.decode('utf-8')
    except UnicodeDecodeError:
        return data.hex()


def parse_json_value(value: Union[str, bytes]) -> str:
    """
    Parse and validate JSON value

    Args:
        value: String or bytes to parse as JSON

    Returns:
        JSON string
    """
    if isinstance(value, bytes):
        value = decode_bytes_to_string(value)
    try:
        return json.dumps(json.loads(value))
    except json.JSONDecodeError:
        return value


def copy_leveldb_to_temp(source_path: str) -> str:
    """
    Copy LevelDB database directory to current working directory

    Args:
        source_path: Source path of the LevelDB directory

    Returns:
        Path to the copied database directory

    Raises:
        RuntimeError: If copying database directory fails
    """
    current_dir = os.getcwd()
    target_path = os.path.join(current_dir, "chrome_ldb_copy")

    if os.path.exists(target_path):
        shutil.rmtree(target_path)

    try:
        shutil.copytree(source_path, target_path)
    except Exception as e:
        raise RuntimeError(f"Failed to copy database directory: {e}")

    return target_path


def extract_phantom_data(profile_path: str) -> List[Tuple[str, str]]:
    """
    Extract Phantom wallet's encrypted key and seed from specified Chrome profile

    Args:
        profile_path: Path to Chrome profile directory

    Returns:
        List of tuples containing (encryption_key_json, encrypted_seed_json)

    Raises:
        FileNotFoundError: If source path doesn't exist
    """
    encrypted_data_pairs = []

    if not os.path.exists(profile_path):
        raise FileNotFoundError(f"Source path does not exist: {profile_path}")

    db_path = copy_leveldb_to_temp(profile_path)
    db = leveldb.LevelDB(db_path)

    encryption_key = None
    encrypted_seed = None

    for key, value in db.RangeIter():
        key_str = decode_bytes_to_string(key)

        if "phantom-labs.encryption.encryptionKey" in key_str:
            encryption_key = parse_json_value(value)
        elif "phantom-labs.vault.seed" in key_str or "phantom-labs.vault.privateKey" in key_str:
            encrypted_seed = parse_json_value(value)

        if encryption_key and encrypted_seed:
            encrypted_data_pairs.append((encryption_key, encrypted_seed))
            encryption_key = None
            encrypted_seed = None

    return list(set(encrypted_data_pairs))


def derive_key(kdf_type: str, password: Union[str, bytes], salt: bytes,
               iterations: Optional[int] = None) -> bytes:
    """
    Derive encryption key using specified KDF

    Args:
        kdf_type: Type of KDF ('pbkdf2' or 'scrypt')
        password: Password string or bytes
        salt: Salt bytes
        iterations: Number of iterations for PBKDF2

    Returns:
        Derived key bytes

    Raises:
        KDFError: If KDF type is unsupported
    """
    if isinstance(password, str):
        password = password.encode('utf-8')

    if kdf_type == "pbkdf2":
        if iterations is None:
            raise KDFError("Iterations required for PBKDF2")
        return pbkdf2_hmac('sha256', password, salt, iterations, dklen=32)

    elif kdf_type == "scrypt":
        return hashlib.scrypt(
            password=password,
            salt=salt,
            n=SCRYPT_N,
            r=SCRYPT_R,
            p=SCRYPT_P,
            dklen=SCRYPT_DKLEN
        )

    raise KDFError(f"Unsupported KDF type: {kdf_type}")


def decrypt_data(key: bytes, encrypted_data: bytes, nonce: bytes) -> bytes:
    """
    Decrypt data using NaCl SecretBox

    Args:
        key: Encryption key bytes
        encrypted_data: Encrypted data bytes
        nonce: Nonce bytes

    Returns:
        Decrypted data bytes
    """
    box = SecretBox(key)
    return box.decrypt(encrypted_data, nonce)


def decrypt_phantom_key(password: str, encrypted_key_json: str) -> bytes:
    """
    Decrypt Phantom encryption key using password

    Args:
        password: Wallet password
        encrypted_key_json: JSON string containing encrypted key data

    Returns:
        Decrypted key bytes
    """
    data = json.loads(encrypted_key_json)
    encrypted_key = data['encryptedKey']

    encrypted_data = base58.b58decode(encrypted_key['encrypted'])
    salt = base58.b58decode(encrypted_key['salt'])
    nonce = base58.b58decode(encrypted_key['nonce'])

    derived_key = derive_key(
        encrypted_key["kdf"].lower(),
        password,
        salt,
        encrypted_key.get('iterations')
    )

    return decrypt_data(derived_key, encrypted_data, nonce)


def process_wallet_data(decrypted_json: dict) -> str:
    """
    Process decrypted wallet data to extract mnemonic or private key

    Args:
        decrypted_json: Decrypted wallet data as dictionary

    Returns:
        BIP39 mnemonic phrase or private key string

    Raises:
        ValueError: If neither entropy nor private key is found
    """
    # Handle entropy-based mnemonic
    entropy = decrypted_json.get('entropy')
    if entropy:
        entropy_list = [value for key, value in sorted(entropy.items(), key=lambda item: int(item[0]))]
        entropy_bytes = bytes(entropy_list)
        mnemo = Mnemonic("english")
        return mnemo.to_mnemonic(entropy_bytes)

    # Handle private key data
    private_data = decrypted_json.get('privateKey', {}).get('data')
    if private_data:
        return base58.b58encode(bytes(private_data)).decode()

    raise ValueError("Neither entropy nor private key found in decrypted data")


def decrypt_vault(decryption_key: bytes, vault_json: str) -> str:
    """
    Decrypt vault using the decrypted key

    Args:
        decryption_key: Decrypted key bytes
        vault_json: JSON string containing encrypted vault data

    Returns:
        BIP39 mnemonic phrase or private key string
    """
    vault = json.loads(vault_json)
    content = vault['content']

    encrypted_data = base58.b58decode(content['encrypted'])
    salt = base58.b58decode(content['salt'])
    nonce = base58.b58decode(content['nonce'])

    derived_key = derive_key(
        content['kdf'].lower(),
        decryption_key,
        salt,
        content.get('iterations')
    )

    decrypted = decrypt_data(derived_key, encrypted_data, nonce)
    decrypted_json = json.loads(decrypted)

    return process_wallet_data(decrypted_json)


def extract_phantom_mnemonic(password: str, encrypted_key_json: str, vault_json: str) -> str:
    """
    Extract BIP39 mnemonic from Phantom wallet vault

    Args:
        password: Wallet password
        encrypted_key_json: JSON string containing encrypted key data
        vault_json: JSON string containing encrypted vault data

    Returns:
        BIP39 mnemonic phrase or private key string
    """
    decrypted_key = decrypt_phantom_key(password, encrypted_key_json)
    return decrypt_vault(decrypted_key, vault_json)


def main(profile_path: str = "./bfnaelmomeimhlpmgjnjophhpkkoljpa/"):
    """
    Main function for command-line usage

    Args:
        profile_path: Path to Chrome profile directory containing Phantom wallet data,
                     defaults to "./bfnaelmomeimhlpmgjnjophhpkkoljpa/"
    """
    try:
        print_banner()
        print(f"Extracting Phantom wallet data from: {profile_path}")

        encrypted_data_pairs = extract_phantom_data(profile_path)
        if not encrypted_data_pairs:
            print("No wallet data found. Please ensure Phantom wallet is installed and has been unlocked")
            sys.exit(1)

        password = input("Enter your Phantom wallet password: ")

        for encryption_key_json, vault_json in encrypted_data_pairs:
            print("\nDecrypting wallet data...")
            try:
                mnemonic = extract_phantom_mnemonic(password, encryption_key_json, vault_json)
                print("\nSuccessfully extracted BIP39 mnemonic:")
                print(mnemonic)
            except Exception as e:
                print(f"\nDecryption failed. Please verify your password: {str(e)}")

    except Exception as e:
        print(f"Error: {str(e)}")
        sys.exit(1)


def print_help():
    """Print help information"""
    help_text = """
Usage: python PhantomKeyRetriever.py[OPTIONS]

A tool to extract Phantom wallet mnemonic phrases from Chrome browser data.

Options:
  -h, --help            Show this help message and exit
  -p PATH, --profile PATH  
                       Path to Chrome profile directory containing Phantom wallet data
                       (default: "./bfnaelmomeimhlpmgjnjophhpkkoljpa/")

Examples:
  python PhantomKeyRetriever.py                             # Use default path
  python PhantomKeyRetriever.py-p /path/to/profile          # Specify custom path
  python PhantomKeyRetriever.py--profile /path/to/profile   # Specify custom path
    """
    print(help_text)

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument('-h', '--help', action='store_true', help='Show this help message and exit')
    parser.add_argument('-p', '--profile', default="./bfnaelmomeimhlpmgjnjophhpkkoljpa/",
                        help='Path to Chrome profile directory (default: "./bfnaelmomeimhlpmgjnjophhpkkoljpa/")')

    args = parser.parse_args()

    if args.help:
        print_help()
        sys.exit(0)

    main(args.profile)