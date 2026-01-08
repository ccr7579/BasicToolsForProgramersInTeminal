# Terminal IT Tools

A collection of useful IT and developer tools in a single Python CLI script. Fast, lightweight, and easy to use directly from your terminal.

## Features

- **Hashing**: MD5, SHA1, SHA256, SHA512
- **Encoding**: Base64, Base32, URL Encoding/Decoding
- **Decoding**: JWT payload decoder
- **Identifiers**: UUID v1, v3, v4, v5
- **Generators**: Secure passwords, Random numbers, Lorem Ipsum text, QR Codes
- **Converters**: Case converter (snake, camel, pascal, kebab), Hex to RGB, RGB to Hex
- **Text**: String reversal, Slugify, Text diff
- **Formatters**: JSON, XML, CSV (Format & Minify)
- **Utilities**: Unix timestamps, Regex tester, Markdown to HTML, HTML to Markdown
- **Smart Features**: Auto-detects tool by input pattern, Fuzzy matches tool names (e.g., `base64encode` -> `base64_encode`)

## Installation

1. Clone or download this repository.
2. Install the required dependencies:

```bash
pip install -r requirements.txt
```

## Usage

Run the `tools.py` script with the desired tool name and input:

```bash
python tools.py <tool_name> <input>
```

### Examples

- **Generate a MD5 hash**:
  ```bash
  python tools.py md5 "hello"
  ```

- **Decode a JWT**:
  ```bash
  python tools.py jwt_decode "<your_jwt_here>"
  ```

- **Generate a QR Code**:
  ```bash
  python tools.py qr_code "https://github.com"
  # Saved to qr_output.png
  ```

- **Convert case**:
  ```bash
  python tools.py case_converter "hello world" "camel"
  # Output: helloWorld
  ```

- **List all tools**:
  ```bash
  python tools.py --list
  ```

## Dependencies

The script uses standard Python libraries for most tasks but requires:
- `markdown` (for Markdown to HTML)
- `qrcode` & `pillow` (for QR Code generation)

These can be installed via `pip install -r requirements.txt`.

## Pro Tip: Set up an Alias

For even faster access, you can set up an alias in your shell (`.zshrc` or `.bashrc`):

```bash
alias tools="python3 /absolute/path/to/tools.py"
```

Then you can simply run:
```bash
tools md5 "hello"
tools "#ffffff"
```