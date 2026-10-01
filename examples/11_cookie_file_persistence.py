"""Save/reload a scoped demo Cookie at a caller-selected, new file path."""

import argparse
import time
from pathlib import Path

from ja3requests import Session, TlsConfig
from ja3requests.cookies import Ja3RequestsCookieJar


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("path", type=Path, help="New demo file; parent must exist")
    args = parser.parse_args()
    if args.path.exists():
        parser.error("Choose a new path; this example does not replace existing files")

    jar = Ja3RequestsCookieJar()
    jar.set(
        "language",
        "en",
        domain="example.com",
        path="/account",
        secure=True,
        expires=int(time.time()) + 3600,
        discard=False,
        rest={"HttpOnly": None, "SameSite": "Lax"},
    )
    with Session(tls_config=TlsConfig.secure(), use_pooling=False) as session:
        session.cookies = jar
        saved = session.save_cookies(args.path)
    with Session(tls_config=TlsConfig.secure(), use_pooling=False) as restarted:
        loaded = restarted.load_cookies(args.path)
        assert saved == loaded == 1
        assert (
            restarted.cookies.get("language", domain="example.com", path="/account")
            == "en"
        )
    print(f"Saved {saved} Cookie; loaded {loaded}. File retained at {args.path}")
    print(
        "Cookie files can contain login tokens. Keep this file private and remove it when no longer needed."
    )


if __name__ == "__main__":
    main()
