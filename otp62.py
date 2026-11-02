#!/usr/bin/env python3
"""otp62 - encrypt a-zA-Z0-9 text with a reusable seed, leaving no trace.

usage:
  otp62.py seed            show a new random 22-char seed (~131 bits)
  otp62.py enc [--no-pad]  encrypt; prints only the ciphertext
  otp62.py dec             decrypt; shows the plaintext until you press Enter

All prompts and secrets stay on the terminal's alternate screen, so they never
reach scrollback, stdout or stderr. Mouse selection is blocked while a secret is
shown, and the clipboard is cleared every time the program exits.

The seed is never cycled over the message (that would be a Vigenere cipher).
A fresh random nonce plus the seed go through PBKDF2, and SHAKE-256 expands the
result into a keystream as long as the message, which is added mod 62. So the
same seed can safely encrypt many messages.

ciphertext = nonce (16) + body + tag (16), all a-zA-Z0-9

By default the body hides the plaintext length: it holds the length, the
plaintext and random filler, 32, 64, 128... characters in all. With --no-pad the
body is exactly as long as the plaintext. dec reads both.
"""
import os
import sys

# Restart isolated before importing anything else. -I ignores PYTHON* variables
# (PYTHONINSPECT would open a REPL holding the secrets) and keeps this folder off
# sys.path (a planted secrets.py next to this file would be imported); -B never
# writes .pyc files.
if not (sys.flags.isolated and sys.flags.dont_write_bytecode):
    os.execv(sys.executable, [sys.executable, "-I", "-B"] + sys.argv)

import contextlib
import getpass
import hashlib
import hmac
import resource
import secrets
import signal
import subprocess
import termios
import warnings

ALPHABET = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
N = len(ALPHABET)
INDEX = {c: i for i, c in enumerate(ALPHABET)}
LIMIT = 256 - 256 % N  # bytes >= 248 are rejected, otherwise 0-7 would be more likely
NONCE_LEN = 16  # ~95 bits, also the KDF salt
TAG_LEN = 16  # ~95 bits
SEED_LEN = 22  # ~131 bits
KDF_ITERATIONS = 1_200_000
LEN_DIGITS = 3  # a padded body starts with the plaintext length in base 62
MIN_PADDED = 32

ALT_SCREEN_ON = "\033[?1049h\033[?2004l\033[H\033[2J"  # no bracketed paste: it adds escape codes
ALT_SCREEN_OFF = "\033[H\033[2J\033[?1049l"
MOUSE_ON = "\033[?1000h\033[?1002h\033[?1006h"  # clicks are reported to us instead of selecting
MOUSE_OFF = "\033[?1006l\033[?1002l\033[?1000l"


def valid(text):
    return all(c in INDEX for c in text)


def digits(key, count):
    """Expand key into count uniform values in [0, 62)."""
    out, size = [], count * 2 + 32
    while len(out) < count:
        out = [b % N for b in hashlib.shake_256(key).digest(size) if b < LIMIT][:count]
        size *= 2
    return out


def derive(seed, nonce):
    # One PBKDF2 block, then cheap subkeys. Asking PBKDF2 for 64 bytes would cost
    # us two blocks while an attacker testing a guess only needs one.
    master = hashlib.pbkdf2_hmac("sha256", seed.encode(), nonce.encode(), KDF_ITERATIONS)
    return (hmac.new(master, b"enc", hashlib.sha256).digest(),
            hmac.new(master, b"mac", hashlib.sha256).digest())


def pad(plaintext):
    """Prefix the length, then fill with random characters up to 32, 64, 128..."""
    n = len(plaintext)
    if n >= N ** LEN_DIGITS:
        raise ValueError("plaintext too long to pad")
    size = MIN_PADDED
    while size < LEN_DIGITS + n:
        size *= 2
    header = "".join(ALPHABET[n // N ** i % N] for i in reversed(range(LEN_DIGITS)))
    filler = "".join(secrets.choice(ALPHABET) for _ in range(size - LEN_DIGITS - n))
    return header + plaintext + filler


def unpad(text):
    n = 0
    for c in text[:LEN_DIGITS]:
        n = n * N + INDEX[c]
    return text[LEN_DIGITS:LEN_DIGITS + n]


def tag(mac_key, nonce, body, padded):
    # Padded bodies MAC one extra byte that can't occur in a-zA-Z0-9, so both
    # formats look alike but the tag tells (and protects) which one it is.
    data = (nonce + body).encode() + (b"\0" if padded else b"")
    mac = hmac.new(mac_key, data, hashlib.sha256).digest()
    return "".join(ALPHABET[d] for d in digits(mac, TAG_LEN))


def encrypt(seed, plaintext, padded=True):
    if padded:
        plaintext = pad(plaintext)
    nonce = "".join(secrets.choice(ALPHABET) for _ in range(NONCE_LEN))
    enc_key, mac_key = derive(seed, nonce)
    stream = digits(enc_key, len(plaintext))
    body = "".join(ALPHABET[(INDEX[c] + k) % N] for c, k in zip(plaintext, stream))
    return nonce + body + tag(mac_key, nonce, body, padded)


def decrypt(seed, ciphertext):
    nonce, body, mac = ciphertext[:NONCE_LEN], ciphertext[NONCE_LEN:-TAG_LEN], ciphertext[-TAG_LEN:]
    enc_key, mac_key = derive(seed, nonce)
    padded = hmac.compare_digest(mac, tag(mac_key, nonce, body, True))
    if not padded and not hmac.compare_digest(mac, tag(mac_key, nonce, body, False)):
        raise ValueError("wrong seed or corrupted ciphertext")
    stream = digits(enc_key, len(body))
    plaintext = "".join(ALPHABET[(INDEX[c] - k) % N] for c, k in zip(body, stream))
    return unpad(plaintext) if padded else plaintext


def ask_secret(prompt, confirm=False):
    value = getpass.getpass(prompt + ": ")
    if confirm and getpass.getpass("Repeat " + prompt[0].lower() + prompt[1:] + ": ") != value:
        raise ValueError("entries did not match")
    return value


def ask(tty, prompt):
    tty.write(prompt.encode())
    line = b""
    while not line.endswith(b"\n"):
        chunk = os.read(tty.fileno(), 4096)
        if not chunk:
            raise EOFError
        line += chunk
    return line.decode(errors="replace").strip()


def show_secret(tty, secret):
    """Show a secret with mouse selection blocked, wipe it on Enter."""
    fd = tty.fileno()
    saved = termios.tcgetattr(fd)
    keys = termios.tcgetattr(fd)
    keys[3] &= ~(termios.ICANON | termios.ECHO | termios.ISIG)  # unechoed bytes, no Ctrl-Z
    keys[6][termios.VMIN], keys[6][termios.VTIME] = 1, 0
    termios.tcsetattr(fd, termios.TCSAFLUSH, keys)
    try:
        tty.write(("\033[H\033[2J" + MOUSE_ON + secret + "\n\n[Enter] wipe screen and clipboard").encode())
        while not set(os.read(fd, 1024)) & {3, 4, 10, 13}:  # Enter, Ctrl-C, Ctrl-D; mouse is ignored
            pass
    finally:
        with contextlib.suppress(OSError, termios.error):
            tty.write((MOUSE_OFF + "\033[H\033[2J").encode())
            termios.tcsetattr(fd, termios.TCSAFLUSH, saved)


@contextlib.contextmanager
def private_screen(tty):
    """Run on the alternate screen, so nothing lands in scrollback."""
    tty.write(ALT_SCREEN_ON.encode())
    try:
        yield
    finally:
        with contextlib.suppress(OSError):
            tty.write(ALT_SCREEN_OFF.encode())


def clear_clipboard():
    # A terminal program can't block Cmd+A Cmd+C, so whatever got copied is dropped on exit.
    with contextlib.suppress(OSError, subprocess.SubprocessError):
        subprocess.run(["/usr/bin/pbcopy"], input=b"", timeout=5)


def interrupt(signum, frame):
    raise KeyboardInterrupt


def main():
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))  # no core dump with secrets in it
    warnings.simplefilter("error", getpass.GetPassWarning)  # never fall back to echoed input
    for sig in (signal.SIGHUP, signal.SIGTERM):  # closing the window still runs the cleanup
        signal.signal(sig, interrupt)
    args = sys.argv[1:]
    if args not in (["seed"], ["enc"], ["enc", "--no-pad"], ["dec"]):
        sys.exit(__doc__)
    cmd = args[0]
    try:
        tty = open("/dev/tty", "r+b", buffering=0)
    except OSError:
        sys.exit("needs a terminal")
    output = None
    try:
        with tty, private_screen(tty):
            if cmd == "seed":
                show_secret(tty, "".join(secrets.choice(ALPHABET) for _ in range(SEED_LEN)))
            elif cmd == "enc":
                seed = ask_secret("Seed", confirm=True)
                if not seed:
                    raise ValueError("empty seed")
                if len(seed) < 16:
                    tty.write(b"warning: short seed, consider `otp62.py seed`\n")
                plaintext = ask_secret("Plaintext (a-zA-Z0-9)", confirm=True)
                # Offending characters are not echoed: they are part of the secret.
                if not plaintext or not valid(plaintext):
                    raise ValueError("plaintext may only contain a-z, A-Z, 0-9")
                output = encrypt(seed, plaintext, padded="--no-pad" not in args)
            else:
                seed = ask_secret("Seed")
                ciphertext = ask(tty, "Ciphertext: ")
                if len(ciphertext) <= NONCE_LEN + TAG_LEN or not valid(ciphertext):
                    raise ValueError("malformed ciphertext")
                show_secret(tty, decrypt(seed, ciphertext))
    except (KeyboardInterrupt, EOFError):
        sys.exit("aborted")
    except getpass.GetPassWarning:
        sys.exit("no terminal to read hidden input from")
    except ValueError as e:
        sys.exit("error: " + str(e))
    finally:
        clear_clipboard()
    if output:
        print(output)


if __name__ == "__main__":
    main()
