# Secure Image Steganography System

A Flask web application that encrypts a secret image and hides it inside a cover image using LSB steganography.

## Run on Windows

1. Install Python 3.11+.
2. Open a terminal in this folder.
3. Create a virtual environment:
   `python -m venv .venv`
4. Activate it:
   `.venv\Scripts\activate`
5. Install dependencies:
   `pip install -r requirements.txt`
6. Start:
   `python app.py`
7. Open `http://127.0.0.1:5000`

## Notes
- Output stego images are PNG because JPEG recompression can destroy LSB data.
- The encrypted payload includes a small header and payload length.
- Use a cover image with enough RGB capacity. Roughly, capacity is 3 bits per pixel before encryption overhead.
