"""ctf-toolkit CLI entry point."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import ciphers, encoders, hashes, textstats

def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="ctf",
        description="Swiss-army CLI for CTF challenges.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    # encode / decode
    enc = sub.add_parser("encode", help="Encode text to a given format.")
    enc.add_argument("format", choices=["b64", "b32", "hex", "url", "rot13", "morse", "binary"])
    enc.add_argument("data")

    dec = sub.add_parser("decode", help="Decode text from a given format.")
    dec.add_argument("format", choices=["b64", "b32", "hex", "url", "rot13", "morse", "binary"])
    dec.add_argument("data")

    # cipher subcommands
    cipher = sub.add_parser("cipher", help="Classical ciphers and breakers.")
    cipher_sub = cipher.add_subparsers(dest="cipher_cmd", required=True)

    cae = cipher_sub.add_parser("caesar", help="Caesar shift cipher.")
    cae.add_argument("--shift", type=int, default=13)
    cae.add_argument("text")

    caebr = cipher_sub.add_parser("caesar-brute", help="Try all 26 Caesar shifts.")
    caebr.add_argument("text")

    vig = cipher_sub.add_parser("vigenere", help="Vigenère cipher.")
    vig.add_argument("--key", required=True)
    vig.add_argument("--decrypt", action="store_true")
    vig.add_argument("text")

    xor = cipher_sub.add_parser("xor", help="XOR-decrypt hex with a key.")
    xor.add_argument("--key", required=True)
    xor.add_argument("hex_data")

    atb = cipher_sub.add_parser("atbash", help="Atbash substitution.")
    atb.add_argument("text")

    # hash subcommands
    h = sub.add_parser("hash", help="Hash identification, computation, cracking.")
    h_sub = h.add_subparsers(dest="hash_cmd", required=True)

    h_id = h_sub.add_parser("id", help="Identify likely algorithm from a digest.")
    h_id.add_argument("digest")

    h_compute = h_sub.add_parser("compute", help="Compute a digest.")
    h_compute.add_argument("--algo", required=True)
    h_compute.add_argument("text")

    h_crack = h_sub.add_parser("crack", help="Dictionary crack.")
    h_crack.add_argument("--algo", required=True)
    h_crack.add_argument("--wordlist", required=True, type=Path)
    h_crack.add_argument("digest")

    # text subcommands
    t = sub.add_parser("text", help="Text statistics.")
    t_sub = t.add_subparsers(dest="text_cmd", required=True)
    t_entropy = t_sub.add_parser("entropy", help="Shannon entropy.")
    t_entropy.add_argument("data")
    t_freq = t_sub.add_parser("freq", help="Letter frequency table.")
    t_freq.add_argument("data")

    args = parser.parse_args(argv)
    return _dispatch(args)

def _dispatch(args: argparse.Namespace) -> int:
    try:
        if args.command == "encode":
            print(encoders.encode(args.format, args.data))
        elif args.command == "decode":
            print(encoders.decode(args.format, args.data))
        elif args.command == "cipher":
            _dispatch_cipher(args)
        elif args.command == "hash":
            _dispatch_hash(args)
        elif args.command == "text":
            _dispatch_text(args)
        else:
            print(f"unknown command: {args.command}", file=sys.stderr)
            return 2
    except (ValueError, FileNotFoundError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    return 0

def _dispatch_cipher(args: argparse.Namespace) -> None:
    if args.cipher_cmd == "caesar":
        print(ciphers.caesar(args.text, args.shift))
    elif args.cipher_cmd == "caesar-brute":
        shift, best, _ = ciphers.caesar_brute(args.text)
        print(f"shift={shift} → {best}")
    elif args.cipher_cmd == "vigenere":
        print(ciphers.vigenere(args.text, args.key, decrypt=args.decrypt))
    elif args.cipher_cmd == "xor":
        plain = ciphers.xor_decrypt(args.hex_data, args.key)
        try:
            print(plain.decode("utf-8"))
        except UnicodeDecodeError:
            print(plain.hex(), "(non-UTF-8)")
    elif args.cipher_cmd == "atbash":
        print(ciphers.atbash(args.text))

def _dispatch_hash(args: argparse.Namespace) -> None:
    if args.hash_cmd == "id":
        guesses = hashes.identify(args.digest)
        print("Likely:", ", ".join(guesses))
    elif args.hash_cmd == "compute":
        print(hashes.compute(args.algo, args.text))
    elif args.hash_cmd == "crack":
        result = hashes.crack(args.algo, args.digest, args.wordlist)
        print(result if result else "(not found in wordlist)")

def _dispatch_text(args: argparse.Namespace) -> None:
    if args.text_cmd == "entropy":
        h = textstats.shannon_entropy(args.data)
        print(f"{h:.3f} bits/char")
    elif args.text_cmd == "freq":
        table = textstats.frequency_table(args.data)
        for letter, freq in table.items():
            bar = "█" * int(freq * 100)
            print(f"  {letter}  {freq*100:5.2f}%  {bar}")

if __name__ == "__main__":
    sys.exit(main())
