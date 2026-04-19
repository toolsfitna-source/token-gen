import json
import os
import sys
import requests as _req_lib

_LICENSE_FILE = os.path.join("config", "license.txt")
_LICENSE_API = "https://fitnatools.xyz/api/islicensevalid"


def _check_license():
    license_key = ""
    if os.path.isfile(_LICENSE_FILE):
        with open(_LICENSE_FILE, "r", encoding="utf-8") as f:
            license_key = f.read().strip()

    if not license_key:
        license_key = input("\033[97m  > Enter your license key: \033[0m").strip()
        if not license_key:
            print("\033[91m[!] No license key provided.\033[0m")
            sys.exit(1)

    try:
        r = _req_lib.post(_LICENSE_API, json={"license": license_key}, timeout=15)
        data = r.json()
        if data.get("valid"):
            os.makedirs(os.path.dirname(_LICENSE_FILE) or ".", exist_ok=True)
            with open(_LICENSE_FILE, "w", encoding="utf-8") as f:
                f.write(license_key)
            print("\033[92m  License valid.\033[0m\n")
            return True
        else:
            print("\033[91m[!] License expired or invalid.\033[0m")
            if os.path.isfile(_LICENSE_FILE):
                os.remove(_LICENSE_FILE)
            sys.exit(1)
    except Exception as e:
        print(f"\033[91m[!] License check failed: {e}\033[0m")
        sys.exit(1)


from utils import Utils
from generator import AccountGenerator, CyberTempMail, HotmailProvider, ZeusProvider

BANNER = """
\033[96m╔══════════════════════════════════════════════╗
║        DISCORD TOKEN GENERATOR v1.0          ║
║        OkHttp + Conscrypt TLS                ║
║        Discord Android 323.12                ║
╚══════════════════════════════════════════════╝\033[0m
"""

_KEYS_FILE = os.path.join("config", "api_keys.json")
_KEYS = {}
if os.path.isfile(_KEYS_FILE):
    with open(_KEYS_FILE, "r", encoding="utf-8") as f:
        _KEYS = json.load(f)


def main():
    print(BANNER)
    #_check_license()

    Utils.load_proxies("config/proxies.txt")

    print("\033[97mMail provider:\033[0m")
    print("  1 : CyberTemp (default)")
    print("  2 : Hotmail / Outlook (IMAP)")
    print("  3 : Zeus (buy Hotmail on-demand)")
    mail_choice = input("  > Choice (default: 1): ").strip()

    mail_provider = None
    if mail_choice == "2":
        mail_file = input("  > Hotmail file path (default: io/input/mails.txt): ").strip() or "io/input/mails.txt"
        tokens_file = input("  > OAuth tokens JSON (leave empty to skip): ").strip() or None
        mail_provider = HotmailProvider(mail_file=mail_file, tokens_file=tokens_file)
    elif mail_choice == "3":
        zeus_key = input("  > Zeus API key: ").strip()
        if not zeus_key:
            print("\033[91m[!] No Zeus API key provided.\033[0m")
            return
        mail_provider = ZeusProvider(api_key=zeus_key)
    else:
        ct_key = _KEYS.get("cybertemp", "")
        if not ct_key:
            ct_key = input("  > CyberTemp API key: ").strip()
        if not ct_key:
            print("\033[91m[!] No CyberTemp API key provided.\033[0m")
            return
        mail_provider = CyberTempMail(api_key=ct_key)

    print("\n\033[97mCaptcha solver:\033[0m")
    print("  1 : aiclientz")
    print("  2 : anysolver")
    print("  3 : OnyxSolver")
    print("  4 : HSJ local + nopecha (default, phone profile silent pass)")
    solver_choice = input("  > Choice (default: 4): ").strip()
    if solver_choice == "1":
        solver_name = "aiclientz"
    elif solver_choice == "2":
        solver_name = "anysolver"
    elif solver_choice == "3":
        solver_name = "onyx"
    else:
        solver_name = "hsj"

    anysolver_provider = "RiskBypass"
    if solver_name == "anysolver":
        print("\n\033[97mAnySolver provider:\033[0m")
        print("  1 : RiskBypass (default)")
        print("  2 : VoidSolver")
        print("  3 : OnyxSolver")
        print("  4 : EZCaptcha")
        print("  5 : AetherSolver")
        print("  6 : BruxSolver")
        prov_choice = input("  > Choice (default: 1): ").strip()
        providers = {
            "1": "RiskBypass", "2": "VoidSolver", "3": "OnyxSolver",
            "4": "EZCaptcha", "5": "AetherSolver", "6": "BruxSolver",
        }
        anysolver_provider = providers.get(prov_choice, "RiskBypass")
        print(f"  Using provider: {anysolver_provider}")

    threads_in = input("\n  > Threads (default: 1): ").strip()
    threads = int(threads_in) if threads_in else 1

    count_in = input("  > Account count (default: 1): ").strip()
    count = int(count_in) if count_in else 1

    print("\n\033[97mRegion:\033[0m")
    print("  1 : EU (default)")
    print("  2 : US")
    region_choice = input("  > Choice (default: 1): ").strip()
    region = "us" if region_choice == "2" else "eu"

    # Locale lock — if all proxies come from one country, fix the Discord
    # locale so the verify email arrives in a predictable language. Otherwise
    # our EU pool rotates across 12 locales and Discord sends emails in all
    # of them (makes mail-filter harder + bot-detectable mismatch).
    if not os.environ.get("RAIDER_FORCE_LOCALE"):
        print("\n\033[97mLocale (shapes UA + headers + Discord email language):\033[0m")
        if region == "us":
            locale_opts = [("en-US", "English (US)")]
        else:
            locale_opts = [
                ("fr-FR", "French"), ("en-GB", "English (UK)"),
                ("de-DE", "German"), ("es-ES", "Spanish"),
                ("it-IT", "Italian"), ("nl-NL", "Dutch"),
                ("pt-PT", "Portuguese"), ("pl-PL", "Polish"),
                ("sv-SE", "Swedish"), ("fi-FI", "Finnish"),
                ("cs-CZ", "Czech"), ("ro-RO", "Romanian"),
            ]
        for i, (code, name) in enumerate(locale_opts, 1):
            suffix = "  [default]" if i == 1 else ""
            print(f"  {i} : {code}  ({name}){suffix}")
        print(f"  {len(locale_opts) + 1} : random (pool rotation — diverse, multilingual emails)")
        loc_choice = input(f"  > Choice (default: 1): ").strip()
        if loc_choice.isdigit() and 1 <= int(loc_choice) <= len(locale_opts):
            os.environ["RAIDER_FORCE_LOCALE"] = locale_opts[int(loc_choice) - 1][0]
        elif loc_choice == str(len(locale_opts) + 1):
            # Random pool — clear the override if set
            os.environ.pop("RAIDER_FORCE_LOCALE", None)
        else:
            os.environ["RAIDER_FORCE_LOCALE"] = locale_opts[0][0]
    forced = os.environ.get("RAIDER_FORCE_LOCALE", "")
    print(f"  \033[96mLocale: {forced if forced else 'random pool'}\033[0m")

    debug_in = input("\n  > Debug mode? (y/n, default: n): ").strip().lower()
    debug = debug_in in ("y", "yes")

    humanize_in = input("  > Humanize (bio + avatar)? (y/n, default: n): ").strip().lower()
    humanize = humanize_in in ("y", "yes")

    logs_in = input("  > Enable per-token logs? (y/n, default: n): ").strip().lower()
    enable_logs = logs_in in ("y", "yes")

    phone_config = None
    phone_in = input("  > Enable phone verify? (y/n, default: n): ").strip().lower()
    if phone_in in ("y", "yes"):
        hero_key = _KEYS.get("hero_sms_api_key", "")
        if not hero_key:
            hero_key = input("  > HeroSMS API key: ").strip()
        if hero_key:
            phone_config = {"enabled": True, "hero_sms_api_key": hero_key, "country": None}

    # When Discord flags the email-verify endpoint and demands a captcha, the
    # default behaviour is to bail (return CAPTCHA_FLAGGED) unless phone verify
    # is enabled. Turn this on to run the captcha solver on email verify too.
    verify_cap_in = input("  > Solve captcha on email verify? (y/n, default: n): ").strip().lower()
    solve_verify_captcha = verify_cap_in in ("y", "yes")

    # Solver fingerprint-mutation mode. Reads RAIDER_AGGRESSIVE_FP_MUTATION from
    # env if already set; otherwise prompt the user here. Applied for every
    # load_profile() call inside the solver package.
    if not os.environ.get("RAIDER_AGGRESSIVE_FP_MUTATION"):
        print("\n\033[97mSolver fingerprint mutation:\033[0m")
        print("  1 : aggressive (full rotation, pool + catalog)  [default]")
        print("  2 : hash-only (4 primary hashes swapped)")
        print("  3 : raw (pristine backbone, no mutation)")
        fm_choice = input("  > Choice (default: 1): ").strip()
        mutation_mode = {"1": "1", "2": "0", "3": "raw"}.get(fm_choice, "1")
        os.environ["RAIDER_AGGRESSIVE_FP_MUTATION"] = mutation_mode
    print(f"  \033[96mSolver mutation mode: {os.environ['RAIDER_AGGRESSIVE_FP_MUTATION']}\033[0m")

    gen = AccountGenerator(
        mail_provider=mail_provider,
        phone_config=phone_config,
        proxy_file="config/proxies.txt",
        output_dir="io/output",
        api_key_aiclientz=_KEYS.get("aiclientz", ""),
        api_key_anysolver=_KEYS.get("anysolver", ""),
        api_key_onyx=_KEYS.get("onyx", ""),
        anysolver_provider=anysolver_provider,
        solver_priority=[solver_name],
        http_backend="okhttp_java",
        enable_logs=enable_logs,
        humanize=humanize,
        science=True,
        region=region,
        debug=debug,
        solve_verify_captcha=solve_verify_captcha,
    )

    gen.run(count=count, threads=threads)


if __name__ == "__main__":
    main()
