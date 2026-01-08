import hashlib
import base64
import uuid
import random
import json
import csv
import argparse
import re
import time
import sys
from io import BytesIO

# ======================
# Hash Functions
# ======================
def md5(text): return hashlib.md5(text.encode()).hexdigest()
def sha1(text): return hashlib.sha1(text.encode()).hexdigest()
def sha256(text): return hashlib.sha256(text.encode()).hexdigest()
def sha512(text): return hashlib.sha512(text.encode()).hexdigest()

# ======================
# Base & URL Encoding
# ======================
def base64_encode(text): return base64.b64encode(text.encode()).decode()
def base64_decode(text): return base64.b64decode(text.encode()).decode()
def base32_encode(text): return base64.b32encode(text.encode()).decode()
def base32_decode(text): return base64.b32decode(text.encode()).decode()

def url_encode(text):
    import urllib.parse
    return urllib.parse.quote(text)

def url_decode(text):
    import urllib.parse
    return urllib.parse.unquote(text)

# ======================
# JWT Decoding
# ======================
def jwt_decode(text):
    try:
        parts = text.split('.')
        if len(parts) != 3:
            return "Invalid JWT format. Must have 3 parts separated by dots."
        payload = parts[1]
        # Fix padding
        payload += '=' * (-len(payload) % 4)
        decoded = base64.b64decode(payload).decode()
        return json.dumps(json.loads(decoded), indent=4)
    except Exception as e:
        return f"Error decoding JWT: {str(e)}"

# ======================
# UUIDs
# ======================
def uuid_generate(version="4"):
    if version=="1": return str(uuid.uuid1())
    elif version=="3": return str(uuid.uuid3(uuid.NAMESPACE_DNS, "example.com"))
    elif version=="4": return str(uuid.uuid4())
    elif version=="5": return str(uuid.uuid5(uuid.NAMESPACE_DNS, "example.com"))

# ======================
# Random Generators
# ======================
def random_password(length=12):
    chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()"
    return ''.join(random.choice(chars) for _ in range(length))

def random_number(start=0, end=100):
    return random.randint(start, end)

def lorem_ipsum(count=3):
    words = "lorem ipsum dolor sit amet consectetur adipiscing elit sed do eiusmod tempor incididunt ut labore et dolore magna aliqua".split()
    return " ".join(random.choice(words) for _ in range(count)).capitalize() + "."

# ======================
# Text Utilities
# ======================
def string_reverse(text): return text[::-1]
def slugify(text): return re.sub(r'\W+', '-', text.lower()).strip('-')

def case_converter(text, style="snake"):
    # Clear special characters and split
    words = re.findall(r'[A-Z]?[a-z]+|[A-Z]+(?=[A-Z][a-z]|\b)|\d+', text)
    if style == "snake":
        return "_".join(w.lower() for w in words)
    elif style == "camel":
        return words[0].lower() + "".join(w.capitalize() for w in words[1:])
    elif style == "pascal":
        return "".join(w.capitalize() for w in words)
    elif style == "kebab":
        return "-".join(w.lower() for w in words)
    return text

def text_diff(a, b):
    import difflib
    diff = difflib.ndiff(a.splitlines(), b.splitlines())
    return '\n'.join(diff)

# ======================
# Color Conversions
# ======================
def hex_to_rgb(hex_code):
    hex_code = hex_code.lstrip('#')
    if len(hex_code) == 3:
        hex_code = ''.join([c*2 for c in hex_code])
    return tuple(int(hex_code[i:i+2], 16) for i in (0, 2, 4))

def rgb_to_hex(r, g, b):
    return '#{:02x}{:02x}{:02x}'.format(int(r), int(g), int(b))

# ======================
# JSON / XML / CSV / Markdown
# ======================
def json_formatter(text):
    try: return json.dumps(json.loads(text), indent=4)
    except: return "Invalid JSON"

def json_minifier(text):
    try: return json.dumps(json.loads(text), separators=(',', ':'))
    except: return "Invalid JSON"

def xml_formatter(text):
    import xml.dom.minidom
    try: return xml.dom.minidom.parseString(text).toprettyxml()
    except: return "Invalid XML"

def xml_minifier(text):
    import xml.dom.minidom
    try: return ''.join(line.strip() for line in xml.dom.minidom.parseString(text).toxml().splitlines())
    except: return "Invalid XML"

def csv_to_json(text):
    try:
        reader = csv.DictReader(text.splitlines())
        return json.dumps(list(reader), indent=4)
    except: return "Invalid CSV"

def json_to_csv(text):
    try:
        data = json.loads(text)
        if not data: return ""
        output = []
        header = data[0].keys()
        output.append(','.join(header))
        for row in data:
            output.append(','.join(str(row.get(h, "")) for h in header))
        return '\n'.join(output)
    except: return "Invalid JSON for CSV conversion"

def markdown_to_html(text):
    try:
        import markdown
        return markdown.markdown(text)
    except ImportError:
        return "Error: 'markdown' library not installed. Run 'pip install markdown'."

def html_to_markdown(text):
    return re.sub(r'<[^>]+>', '', text)

# ======================
# Timestamp Utilities
# ======================
def unix_timestamp(): return int(time.time())
def timestamp_converter(ts):
    try: return time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(int(ts)))
    except: return "Invalid Timestamp"

# ======================
# Regex Tester
# ======================
def regex_tester(pattern, text):
    try:
        matches = re.findall(pattern, text)
        return matches if matches else "No match found"
    except Exception as e:
        return f"Regex Error: {str(e)}"

# ======================
# QR Code Generator
# ======================
def qr_code(text):
    try:
        import qrcode
        qr = qrcode.QRCode()
        qr.add_data(text)
        qr.make(fit=True)
        img = qr.make_image(fill="black", back_color="white")
        buffer = BytesIO()
        img.save(buffer, format="PNG")
        return buffer.getvalue()
    except ImportError:
        print("Error: 'qrcode' and 'pillow' libraries not installed. Run 'pip install qrcode pillow'.")
        return None

# ======================
# Tool Mapping & Execution
# ======================
TOOLS = {
    "md5": (md5, 1),
    "sha1": (sha1, 1),
    "sha256": (sha256, 1),
    "sha512": (sha512, 1),
    "base64_encode": (base64_encode, 1),
    "base64_decode": (base64_decode, 1),
    "base32_encode": (base32_encode, 1),
    "base32_decode": (base32_decode, 1),
    "url_encode": (url_encode, 1),
    "url_decode": (url_decode, 1),
    "jwt_decode": (jwt_decode, 1),
    "uuid_v1": (lambda: uuid_generate("1"), 0),
    "uuid_v3": (lambda: uuid_generate("3"), 0),
    "uuid_v4": (lambda: uuid_generate("4"), 0),
    "uuid_v5": (lambda: uuid_generate("5"), 0),
    "random_password": (lambda x=12: random_password(int(x)), 1),
    "random_number": (lambda x=0, y=100: random_number(int(x), int(y)), 2),
    "lorem_ipsum": (lambda x=10: lorem_ipsum(int(x)), 1),
    "string_reverse": (string_reverse, 1),
    "slugify": (slugify, 1),
    "case_converter": (lambda text, style="snake": case_converter(text, style), 2),
    "text_diff": (text_diff, 2),
    "hex_to_rgb": (hex_to_rgb, 1),
    "rgb_to_hex": (lambda r, g, b: rgb_to_hex(r, g, b), 3),
    "json_formatter": (json_formatter, 1),
    "json_minifier": (json_minifier, 1),
    "xml_formatter": (xml_formatter, 1),
    "xml_minifier": (xml_minifier, 1),
    "csv_to_json": (csv_to_json, 1),
    "json_to_csv": (json_to_csv, 1),
    "markdown_to_html": (markdown_to_html, 1),
    "html_to_markdown": (html_to_markdown, 1),
    "unix_timestamp": (unix_timestamp, 0),
    "timestamp_converter": (timestamp_converter, 1),
    "regex_tester": (regex_tester, 2),
    "qr_code": (qr_code, 1)
}

def detect_tool(input_text):
    """Detect tool based on input pattern."""
    patterns = [
        (r'^[a-zA-Z0-9\-_]+\.[a-zA-Z0-9\-_]+\.[a-zA-Z0-9\-_]+$', 'jwt_decode'),
        (r'^#(?:[0-9a-fA-F]{3}){1,2}$', 'hex_to_rgb'),
        (r'^[0-9]{10,13}$', 'timestamp_converter'),
        (r'^https?://[^\s/$.?#].[^\s]*$', 'url_decode'), # Simple URL detection
        (r'^\{.*\}$|^\[.*\]$', 'json_formatter'),
        (r'^<.*>$', 'xml_formatter'),
    ]
    for pattern, tool in patterns:
        if re.match(pattern, input_text.strip()):
            return tool
    return None

def fuzzy_match(tool_name):
    """Find the closest match for a tool name."""
    import difflib
    # Normalize by removing underscores for comparison as well
    normalized_keys = {k.replace('_', ''): k for k in TOOLS.keys()}
    match = normalized_keys.get(tool_name.replace('_', ''))
    if match:
        return match
    
    # Fallback to standard difflib for typos
    matches = difflib.get_close_matches(tool_name, TOOLS.keys(), n=1, cutoff=0.6)
    return matches[0] if matches else None

def list_tools():
    print("\nAvailable IT Tools (Terminal Version):")
    for key in sorted(TOOLS.keys()):
        print("  •", key)
    print("\nUsage examples:")
    print("  python tools.py md5 'hello'")
    print("  python tools.py base64encode 'hello' (Fuzzy matches base64_encode)")
    print("  python tools.py '#ffffff' (Auto-detects Hex to RGB)")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Terminal IT Tools")
    parser.add_argument("tool", nargs="?", help="Tool or input for auto-detection")
    parser.add_argument("input", nargs="*", help="Input text or numbers")
    parser.add_argument("--list", action="store_true", help="List all tools")
    args = parser.parse_args()

    if args.list:
        list_tools()
        sys.exit()

    if not args.tool:
        list_tools()
        sys.exit()

    tool_name = args.tool
    input_args = args.input

    # 1. Exact match check
    if tool_name not in TOOLS:
        # 2. Try pattern auto-detection
        detected = detect_tool(tool_name)
        if detected:
            print(f"Detected Tool (by pattern): {detected}")
            input_args = [tool_name] + input_args
            tool_name = detected
        else:
            # 3. Try fuzzy matching
            matched = fuzzy_match(tool_name)
            if matched:
                print(f"Using closest match: {matched}")
                tool_name = matched
            else:
                print(f"Tool '{tool_name}' not found and no close match or pattern detected.")
                print("Use --list to see all tools.")
                sys.exit()

    func, arg_count = TOOLS[tool_name]
    
    try:
        if tool_name == "qr_code":
            if not input_args:
                print("Provide text for QR code")
                sys.exit()
            data = func(" ".join(input_args))
            if data:
                with open("qr_output.png", "wb") as f:
                    f.write(data)
                print("QR code saved to qr_output.png")
        elif arg_count == 0:
            print(func())
        elif arg_count == 1:
            inp = " ".join(input_args) if input_args else ""
            print(func(inp))
        else:
            if len(input_args) < arg_count:
                print(f"Tool '{tool_name}' requires {arg_count} arguments.")
                sys.exit()
            print(func(*input_args[:arg_count]))
    except Exception as e:
        print(f"Error executing {tool_name}: {str(e)}")

