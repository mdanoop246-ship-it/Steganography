from PIL import Image
import struct

MAGIC = b"STEGIMG1"

def _bytes_to_bits(data):
    for byte in data:
        for shift in range(7, -1, -1):
            yield (byte >> shift) & 1

def _bits_to_bytes(bits):
    out = bytearray()
    for i in range(0, len(bits), 8):
        chunk = bits[i:i+8]
        if len(chunk) < 8:
            break
        value = 0
        for bit in chunk:
            value = (value << 1) | bit
        out.append(value)
    return bytes(out)

def encode_payload(cover: Image.Image, payload: bytes) -> Image.Image:
    cover = cover.convert("RGB")
    raw = MAGIC + struct.pack(">I", len(payload)) + payload
    bits = list(_bytes_to_bits(raw))
    capacity = cover.width * cover.height * 3
    if len(bits) > capacity:
        max_bytes = max(0, (capacity // 8) - len(MAGIC) - 4)
        raise ValueError(f"Secret is too large for this cover image. Maximum encrypted payload is about {max_bytes:,} bytes.")
    pixels = list(cover.getdata())
    out = []
    i = 0
    for r, g, b in pixels:
        channels = [r, g, b]
        for c in range(3):
            if i < len(bits):
                channels[c] = (channels[c] & 0xFE) | bits[i]
                i += 1
        out.append(tuple(channels))
    stego = Image.new("RGB", cover.size)
    stego.putdata(out)
    return stego

def decode_payload(stego: Image.Image) -> bytes:
    stego = stego.convert("RGB")
    bits = []
    for r, g, b in stego.getdata():
        bits.extend([r & 1, g & 1, b & 1])
    header_bits = bits[:(len(MAGIC)+4)*8]
    header = _bits_to_bytes(header_bits)
    if len(header) < len(MAGIC)+4 or header[:len(MAGIC)] != MAGIC:
        raise ValueError("No valid steganography payload found.")
    length = struct.unpack(">I", header[len(MAGIC):len(MAGIC)+4])[0]
    start = (len(MAGIC)+4)*8
    end = start + length*8
    if end > len(bits):
        raise ValueError("Payload is incomplete or corrupted.")
    return _bits_to_bytes(bits[start:end])
