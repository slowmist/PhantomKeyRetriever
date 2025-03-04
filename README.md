# Phantom Wallet Extractor

A tool to extract Phantom wallet mnemonic phrases and private keys from Chrome browser data, developed by SlowMist Team.

## Features

- Extract Phantom wallet encrypted data from Chrome browser
- Support both PBKDF2 and Scrypt key derivation functions
- Handle both mnemonic phrases and private keys
- User-friendly command-line interface

## Prerequisites

- Python 3.7 or higher
- Chrome browser with Phantom wallet extension installed

## Installation

1. Clone the repository:
```bash
git clone https://github.com/slowmist/PhantomKeyRetriever.git
cd PhantomKeyRetriever
```

2. Install required dependencies:
```bash
pip install -r requirements.txt
```

## Dependencies

- leveldb>=0.201
- base58>=2.1.1
- pynacl>=1.5.0
- mnemonic>=0.20

## Usage

```bash
python PhantomKeyRetriever.py [OPTIONS]
```

### Options

- `-h, --help`: Show help message and exit
- `-p PATH, --profile PATH`: Path to Chrome profile directory containing Phantom wallet data
                          (default: "./bfnaelmomeimhlpmgjnjophhpkkoljpa/")

### Examples

```bash
# Use default profile path
python PhantomKeyRetriever.py

# Specify custom profile path
python PhantomKeyRetriever.py -p /path/to/profile

# Show help message
python PhantomKeyRetriever.py --help
```

## Chrome Profile Location

The Chrome profile directory containing Phantom wallet data is typically located at:

- Windows: `%LOCALAPPDATA%\Google\Chrome\User Data\Default\Local Extension Settings\bfnaelmomeimhlpmgjnjophhpkkoljpa`
- MacOS: `~/Library/Application Support/Google/Chrome/Default/Local Extension Settings/bfnaelmomeimhlpmgjnjophhpkkoljpa`
- Linux: `~/.config/google-chrome/Default/Local Extension Settings/bfnaelmomeimhlpmgjnjophhpkkoljpa`

## Output

The tool will output:
1. Extracted BIP39 mnemonic phrase (if available)
2. Private key (if available)

## Contributing

We welcome contributions! Please feel free to submit a Pull Request.

## Note

This tool is for educational and research purposes only. Make sure you have the right to access the wallet data before using this tool.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Authors

- [@SlowMist Team](https://github.com/slowmist)