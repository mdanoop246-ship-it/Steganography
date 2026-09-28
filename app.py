from flask import Flask, render_template, request, send_file, flash, redirect, url_for
from steganography.crypto import encrypt_bytes, decrypt_bytes
from steganography.encoder import encode_payload, decode_payload
from steganography.metrics import image_metrics
from PIL import Image
import io, os, uuid

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "dev-secret-change-me")
UPLOAD_DIR = "uploads"
OUTPUT_DIR = "output"
os.makedirs(UPLOAD_DIR, exist_ok=True)
os.makedirs(OUTPUT_DIR, exist_ok=True)


def prepare_secret_payload(secret_file, password, cover_img):
    """Prepare an encrypted secret that fits inside the selected cover.

    The original bytes are used when they fit. Otherwise the secret image is
    automatically resized and JPEG-compressed until the encrypted payload fits.
    """
    original_bytes = secret_file.read()
    if not original_bytes:
        raise ValueError("The secret image is empty.")

    try:
        source = Image.open(io.BytesIO(original_bytes))
        source.load()
    except Exception:
        raise ValueError("The secret file is not a valid image.")

    capacity_bytes = (cover_img.width * cover_img.height * 3) // 8
    # 12 bytes = MAGIC (8) + payload length (4), plus encryption overhead.
    usable_capacity = max(0, capacity_bytes - 12)

    encrypted = encrypt_bytes(original_bytes, password)
    if len(encrypted) <= usable_capacity:
        return encrypted, False

    # If the original is too large, automatically make a JPEG copy.
    rgb = source.convert("RGB")
    original_w, original_h = rgb.size

    # Try several quality/size combinations. This makes ordinary phone photos
    # and screenshots usable without asking the user to resize them manually.
    scales = [1.0, 0.9, 0.8, 0.7, 0.6, 0.5, 0.4, 0.3, 0.25]
    qualities = [85, 75, 65, 55]

    best_size = None
    best_bytes = None

    for scale in scales:
        w = max(64, int(original_w * scale))
        h = max(64, int(original_h * scale))
        resized = rgb.resize((w, h), Image.Resampling.LANCZOS)

        for quality in qualities:
            buf = io.BytesIO()
            resized.save(buf, format="JPEG", quality=quality, optimize=True)
            candidate = buf.getvalue()
            best_size = (w, h, quality)
            best_bytes = candidate

            encrypted_candidate = encrypt_bytes(candidate, password)
            if len(encrypted_candidate) <= usable_capacity:
                return encrypted_candidate, True

    raise ValueError(
        f"Secret image is still too large for this cover. "
        f"Maximum encrypted payload is about {usable_capacity:,} bytes. "
        f"Please choose a larger cover image."
    )


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/encode", methods=["GET", "POST"])
def encode():
    if request.method == "GET":
        return render_template("encode.html")

    cover = request.files.get("cover")
    secret = request.files.get("secret")
    password = request.form.get("password", "")

    if not cover or not secret or not password:
        flash("Cover image, secret image, and password are required.", "error")
        return redirect(url_for("encode"))

    try:
        cover_img = Image.open(cover).convert("RGB")

        encrypted, adjusted = prepare_secret_payload(secret, password, cover_img)
        stego = encode_payload(cover_img, encrypted)

        name = f"stego_{uuid.uuid4().hex[:10]}.png"
        path = os.path.join(OUTPUT_DIR, name)
        # PNG is required so JPEG recompression does not destroy the LSB payload.
        stego.save(path, "PNG")

        metrics = image_metrics(cover_img, stego)
        if adjusted:
            flash(
                "The secret image was automatically resized/compressed to fit the cover image.",
                "success"
            )

        return render_template(
            "result.html",
            mode="encode",
            filename=name,
            metrics=metrics
        )

    except ValueError as e:
        flash(str(e), "error")
        return redirect(url_for("encode"))
    except Exception as e:
        flash(f"Could not hide the image: {e}", "error")
        return redirect(url_for("encode"))


@app.route("/decode", methods=["GET", "POST"])
def decode():
    if request.method == "GET":
        return render_template("decode.html")

    stego_file = request.files.get("stego")
    password = request.form.get("password", "")

    if not stego_file or not password:
        flash("Stego image and password are required.", "error")
        return redirect(url_for("decode"))

    try:
        stego_img = Image.open(stego_file).convert("RGB")
        encrypted = decode_payload(stego_img)
        secret_bytes = decrypt_bytes(encrypted, password)

        # Detect the recovered image format and preserve it when possible.
        recovered = Image.open(io.BytesIO(secret_bytes))
        recovered.verify()
        recovered = Image.open(io.BytesIO(secret_bytes))
        image_format = (recovered.format or "PNG").upper()

        extension_map = {
            "JPEG": "jpg",
            "PNG": "png",
            "WEBP": "webp",
            "BMP": "bmp",
            "GIF": "gif",
        }
        extension = extension_map.get(image_format, "png")

        name = f"extracted_{uuid.uuid4().hex[:10]}.{extension}"
        path = os.path.join(OUTPUT_DIR, name)
        with open(path, "wb") as f:
            f.write(secret_bytes)

        return render_template(
            "result.html",
            mode="decode",
            filename=name,
            metrics=None
        )

    except Exception:
        flash(
            "Extraction failed. Check the password and ensure the image was not modified.",
            "error"
        )
        return redirect(url_for("decode"))


@app.route("/download/<path:filename>")
def download(filename):
    return send_file(os.path.join(OUTPUT_DIR, filename), as_attachment=True)


if __name__ == "__main__":
    app.run(debug=True)
