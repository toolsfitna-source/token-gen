import threading
import time
import requests


_LOG_COLORS = {
    "SUCCESS": "\033[92m",
    "CAPTCHA": "\033[96m",
    "ERROR":   "\033[91m",
    "WARN":    "\033[93m",
    "INFO":    "\033[97m",
    "DEBUG":   "\033[90m",
}
_LOG_RESET = "\033[0m"

HCAPTCHA_SITEKEY = "e2f713c5-b5ce-41d0-b65f-29823df542cf"
HCAPTCHA_HOST = f"https://{HCAPTCHA_SITEKEY}.react-native.hcaptcha.com"


def _log(level: str, msg: str):
    color = _LOG_COLORS.get(level, "")
    print(f"{color}{msg}{_LOG_RESET}")


_aiclientz_semaphore = threading.Semaphore(5)


def solve_hsj_local(sitekey: str, rqdata: str, proxy_raw: str,
                    proxy_url: str = None,
                    user_agent: str = "",
                    device_info: dict = None) -> str | None:
    """Local HSJ solver with phone profile replay — context="register" for TokenGen."""
    if not proxy_url and proxy_raw:
        try:
            h, p, u, pw = proxy_raw.split(":", 3)
            proxy_url = f"http://{u}:{pw}@{h}:{p}"
        except ValueError:
            proxy_url = proxy_raw or ""
    try:
        from solver import solve_hcaptcha
        _log("CAPTCHA", f"[hsj] Solving locally (context=register)...")
        token = solve_hcaptcha(
            sitekey=sitekey,
            rqdata=rqdata or "",
            proxy=proxy_url or "",
            host=f"{sitekey}.react-native.hcaptcha.com",
            href="data:text/html;charset=utf-8;base64,",
            user_agent=user_agent,
            device_info=device_info,
            context="register",
        )
        if token:
            return token
        _log("WARN", "[hsj] solve failed")
        return None
    except ImportError as e:
        _log("ERROR", f"[hsj] brux_source not found: {e}")
        return None
    except Exception as e:
        _log("ERROR", f"[hsj] exception: {type(e).__name__}: {e}")
        return None


def solve_aiclientz(api_key: str, sitekey: str, rqdata: str,
                    proxy_raw: str, proxy_url: str = None) -> str | None:
    _aiclientz_semaphore.acquire()
    try:
        return _solve_aiclientz_inner(api_key, sitekey, rqdata, proxy_raw, proxy_url)
    finally:
        _aiclientz_semaphore.release()


def _solve_aiclientz_inner(api_key, sitekey, rqdata, proxy_raw, proxy_url=None):
    BASE = "http://captcha.aiclientz.com:1234"
    if not proxy_url and proxy_raw:
        try:
            h, p, u, pw = proxy_raw.split(":", 3)
            proxy_url = f"http://{u}:{pw}@{h}:{p}"
        except ValueError:
            proxy_url = proxy_raw

    body = {
        "site_key": sitekey,
        "site_url": "https://discord.com",
        "rqd": rqdata or "",
        "proxy": proxy_url or "",
        "key": api_key,
    }
    try:
        _log("CAPTCHA", "[aiclientz] Submitting solve request...")
        r = requests.post(f"{BASE}/solve", json=body, timeout=60)
        data = r.json()
        code = str(data.get("code", ""))
        if code == "201":
            token = data.get("captcha", "")
            if token:
                _log("SUCCESS", f"[aiclientz] solved: {token[:40]}...")
                return token
            _log("ERROR", "[aiclientz] code 201 but no captcha token")
            return None
        elif code == "301":
            _log("ERROR", "[aiclientz] Unknown Key")
        elif code == "401":
            _log("ERROR", "[aiclientz] Refund")
        elif code == "407":
            _log("ERROR", "[aiclientz] Low Balance")
        else:
            _log("ERROR", f"[aiclientz] unexpected response: {data}")
    except Exception as e:
        _log("ERROR", f"[aiclientz] exception: {e}")
    return None


def solve_anysolver(api_key: str, sitekey: str, rqdata: str,
                    proxy_raw: str, sub_solver: str = None,
                    user_agent: str = None) -> str | None:
    API = "https://api.anysolver.com"

    proxy_str = ""
    if proxy_raw:
        try:
            h, p, u, pw = proxy_raw.split(":", 3)
            proxy_str = f"http://{u}:{pw}@{h}:{p}"
        except ValueError:
            proxy_str = proxy_raw

    task = {
        "type": "PopularCaptchaEnterpriseToken",
        "websiteURL": "https://discord.com",
        "websiteKey": sitekey,
        "proxy": proxy_str,
    }
    if rqdata:
        task["rqdata"] = rqdata
    if user_agent:
        task["userAgent"] = user_agent

    provider = sub_solver or "RiskBypass"

    create_body = {
        "clientKey": api_key,
        "task": task,
        "provider": provider,
    }

    try:
        _log("CAPTCHA", f"[anysolver] Submitting solve request (provider={provider})...")
        r = requests.post(f"{API}/createTask", json=create_body, timeout=30)
        data = r.json()

        if data.get("errorId", 0) != 0:
            _log("ERROR", f"[anysolver] createTask error: {data.get('errorCode')} — {data.get('errorDescription', '')}")
            return None

        task_id = data.get("taskId")
        if not task_id:
            _log("ERROR", f"[anysolver] no taskId: {data}")
            return None

        time.sleep(4)
        for _ in range(30):
            poll = requests.post(f"{API}/getTaskResult", json={
                "clientKey": api_key,
                "taskId": task_id,
            }, timeout=15).json()

            status = poll.get("status")
            if status == "ready":
                token = poll.get("solution", {}).get("token", "")
                if token:
                    _log("SUCCESS", f"[anysolver] solved: {token[:40]}...")
                    return token
                _log("ERROR", f"[anysolver] ready but no token: {poll}")
                return None
            elif status == "failed":
                _log("ERROR", f"[anysolver] failed: {poll.get('errorCode')} — {poll.get('errorDescription', '')}")
                return None

            time.sleep(3)

        _log("ERROR", "[anysolver] timeout after 90s polling")
        return None
    except Exception as e:
        _log("ERROR", f"[anysolver] exception: {e}")
        return None


def solve_onyx(api_key: str, sitekey: str, rqdata: str,
               proxy_raw: str, web: bool = False) -> tuple[str, str] | None:
    BASE = "https://onyxsolver.io"
    pageurl = "https://discord.com" if web else HCAPTCHA_HOST

    task = {
        "websiteURL": pageurl,
        "websiteKey": sitekey,
        "isInvisible": False,
    }
    if rqdata:
        task["rqdata"] = rqdata

    if proxy_raw:
        try:
            host, port, user, pwd = proxy_raw.split(":", 3)
            task["type"] = "PopularCaptchaTask"
            task["proxy"] = f"{user}:{pwd}@{host}:{port}"
        except ValueError:
            _log("ERROR", "[onyx] proxy format error (expected host:port:user:pass)")
            return None
    else:
        task["type"] = "PopularCaptchaTaskProxyless"

    body = {"clientKey": api_key, "task": task}

    try:
        _log("CAPTCHA", "[onyx] submitting to OnyxSolver...")
        r = requests.post(f"{BASE}/api/createTask", json=body, timeout=30)
        if r.status_code != 200:
            _log("ERROR", f"[onyx] createTask error (HTTP {r.status_code}): {r.text[:200]}")
            return None
        data = r.json()
        if data.get("errorId") != 0:
            _log("ERROR", f"[onyx] createTask error: {data.get('errorDescription') or data}")
            return None
        task_id = data.get("taskId")
        if not task_id:
            _log("ERROR", f"[onyx] no taskId in response: {data}")
            return None
        _log("INFO", f"[onyx] task created: {task_id}")

        for _ in range(60):
            time.sleep(3)
            res = requests.post(
                f"{BASE}/api/getTaskResult",
                json={"clientKey": api_key, "taskId": task_id},
                timeout=15,
            )
            rd = res.json()
            if rd.get("errorId") != 0:
                _log("ERROR", f"[onyx] polling error: {rd.get('errorDescription')}")
                return None
            status = rd.get("status")
            if status == "ready":
                token = rd.get("solution", {}).get("gRecaptchaResponse", "")
                if token:
                    _log("SUCCESS", f"[onyx] solved: {token[:40]}...")
                    return (token, task_id)
                _log("ERROR", f"[onyx] ready but no token: {rd}")
                return None
            if status == "processing":
                continue
            _log("ERROR", f"[onyx] unknown status: {rd}")
            return None
        _log("ERROR", "[onyx] timeout after 3 min")
    except Exception as e:
        _log("ERROR", f"[onyx] exception: {e!r}")
    return None


def report_onyx(api_key: str, task_id: str, is_success: bool) -> None:
    if not task_id or not api_key:
        return
    try:
        result_str = "success" if is_success else "invalid"
        requests.post(
            "https://onyxsolver.io/api/reportTaskResult",
            json={
                "clientKey": api_key,
                "taskId": task_id,
                "result": result_str,
            },
            timeout=5,
        )
        _log("DEBUG", f"[onyx] reported {result_str} for {task_id[:12]}")
    except Exception:
        pass
