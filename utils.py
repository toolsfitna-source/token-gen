import os
import os
import random
from typing import List, Optional, Dict


class Utils:
    _proxies: List[str] = []
    _bad_proxy_path = "config/bad_proxies.txt"
    _bad_proxies: set = set()

    @staticmethod
    def parse_token_line(line: str) -> str:
        line = line.strip()
        if ":" in line:
            parts = line.split(":")
            if len(parts) >= 3 and "@" in parts[0]:
                return parts[-1]
        return line

    @staticmethod
    def read_tokens(filename: str) -> List[str]:
        with open(filename, "r", encoding="utf-8-sig") as f:
            tokens = []
            for line in f:
                line = line.strip()
                if not line:
                    continue
                tokens.append(Utils.parse_token_line(line))
            return tokens

    @classmethod
    def load_bad_proxies(cls):
        if not os.path.exists(cls._bad_proxy_path):
            os.makedirs(os.path.dirname(cls._bad_proxy_path), exist_ok=True)
            with open(cls._bad_proxy_path, "w", encoding="utf-8") as f:
                pass
        with open(cls._bad_proxy_path, "r", encoding="utf-8") as f:
            cls._bad_proxies = set(line.strip() for line in f if line.strip())

    @classmethod
    def load_proxies(cls, path="config/proxies.txt"):
        with open(path, "r", encoding="utf-8") as f:
            all_proxies = [line.strip() for line in f if line.strip()]
        cls.load_bad_proxies()
        cls._proxies = [p for p in all_proxies if p not in cls._bad_proxies]
        print(f"[proxies] loaded {len(cls._proxies)} proxies (filtered {len(all_proxies) - len(cls._proxies)} bad)")

    @classmethod
    def mark_proxy_as_bad(cls, proxy: str):
        if proxy not in cls._bad_proxies:
            with open(cls._bad_proxy_path, "a", encoding="utf-8") as f:
                f.write(proxy + "\n")
            cls._bad_proxies.add(proxy)

    @classmethod
    def get_random_proxy(cls) -> str:
        if not cls._proxies:
            raise RuntimeError("Proxies not loaded or exhausted. Call Utils.load_proxies() first.")
        return random.choice(cls._proxies)
