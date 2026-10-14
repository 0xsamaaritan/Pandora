"""One-time interactive Telegram login for the `telegram` dark-mode source.

Run ONCE to create the session file, then the telegram source can search:

    python -m pandora.telegram_login --config config.yaml

It uses YOUR OWN Telegram API credentials (api_id / api_hash from
https://my.telegram.org). You will be asked for your phone number and the login
code Telegram sends you. Use a DEDICATED account, not your primary personal
number. The resulting session file is account access — keep it private (it is
stored under state/, which is git-ignored).
"""
from __future__ import annotations

import argparse
import os
import sys

import yaml


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="pandora.telegram_login")
    ap.add_argument("--config", required=True, help="path to config YAML")
    args = ap.parse_args(argv)

    with open(args.config, "r", encoding="utf-8") as fh:
        cfg = yaml.safe_load(fh) or {}

    api_id = cfg.get("telegram_api_id")
    api_hash = cfg.get("telegram_api_hash")
    session = cfg.get("telegram_session", "state/tg.session")
    if not (api_id and api_hash):
        print("Set telegram_api_id and telegram_api_hash in your config first "
              "(get them free at https://my.telegram.org).")
        return 1
    try:
        from telethon.sync import TelegramClient
    except ImportError:
        print("telethon is not installed. Run:  pip install telethon")
        return 1

    os.makedirs(os.path.dirname(session) or ".", exist_ok=True)
    print("Starting Telegram login (you'll be asked for your phone + code)...")
    with TelegramClient(session, int(api_id), api_hash) as client:
        me = client.get_me()
        who = getattr(me, "username", None) or getattr(me, "id", "?")
        print(f"Logged in as {who}. Session saved to: {session}")
        print("You can now run:  python -m pandora --config <cfg> --mode dark -v")
    return 0


if __name__ == "__main__":
    sys.exit(main())
