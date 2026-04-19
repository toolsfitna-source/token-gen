import json as _json_module
import json as _json_module
import os
import sys
import threading
from urllib.parse import urlparse, urlencode

_DEBUG = False


def set_debug(val: bool):
    global _DEBUG
    _DEBUG = val


class _CaseInsensitiveDict(dict):

    def __init__(self, data=None):
        super().__init__()
        if data:
            for k, v in (data.items() if hasattr(data, "items") else data):
                self[k] = v

    def __setitem__(self, key, value):
        super().__setitem__(key.lower(), value)

    def __getitem__(self, key):
        return super().__getitem__(key.lower())

    def __contains__(self, key):
        return super().__contains__(key.lower())

    def __delitem__(self, key):
        super().__delitem__(key.lower())

    def get(self, key, default=None):
        return super().get(key.lower(), default)


class _OkHttpResponse:
    __slots__ = ("status_code", "text", "content", "headers", "url", "_set_cookies")

    def __init__(self, data: dict):
        self.status_code = data["status"]
        self.text = data.get("body", "")
        self.url = data.get("url", "")
        body_b64 = data.get("body_b64", "")
        if body_b64:
            import base64 as _b64
            self.content = _b64.b64decode(body_b64)
            if not self.text:
                self.text = ""
        else:
            self.content = self.text.encode("utf-8", errors="replace") if self.text else b""
        self._set_cookies = []
        raw = []
        ce = ""
        for name, value in data.get("headers", []):
            raw.append((name, value))
            if name.lower() == "set-cookie":
                self._set_cookies.append(value)
            elif name.lower() == "content-encoding":
                ce = value.lower()
        self.headers = _CaseInsensitiveDict(raw)
        # Java OkHttp proxy returns compressed bytes when we send explicit
        # Accept-Encoding (OkHttp won't auto-decompress in that case). Decode
        # client-side so .text / .json() work transparently.
        # If Content-Encoding header is missing but body starts with known
        # compression magic bytes, sniff the encoding.
        if not ce and self.content[:2] == b"\x1f\x8b":
            ce = "gzip"
        elif not ce and self.content[:4] == b"\x28\xb5\x2f\xfd":
            ce = "zstd"
        if ce and self.content:
            try:
                raw_bytes = self.content
                # When body came as text, content may already be utf-8-re-encoded
                # garbage. Re-read original bytes from text via latin-1.
                if not body_b64:
                    raw_bytes = self.text.encode("latin-1", errors="replace")
                if ce == "gzip":
                    import gzip as _gz
                    self.content = _gz.decompress(raw_bytes)
                elif ce == "br":
                    import brotli as _br  # type: ignore
                    self.content = _br.decompress(raw_bytes)
                elif ce == "deflate":
                    import zlib as _zl
                    self.content = _zl.decompress(raw_bytes)
                elif ce == "zstd":
                    import zstandard as _zs  # type: ignore
                    self.content = _zs.ZstdDecompressor().decompress(raw_bytes)
                try:
                    self.text = self.content.decode("utf-8")
                except UnicodeDecodeError:
                    self.text = self.content.decode("latin-1", errors="replace")
            except Exception as _e:
                import os as _os
                if _os.environ.get("HSJ_DEBUG"):
                    print(f"[http_client] decompress({ce}) failed: {_e}")

    def json(self):
        if self.text:
            return _json_module.loads(self.text)
        try:
            return _json_module.loads(self.content.decode("utf-8"))
        except UnicodeDecodeError:
            return _json_module.loads(self.content.decode("latin-1"))


class _OkHttpProxyManager:
    _instance = None
    _lock = threading.Lock()
    _backend = "okhttp_java"

    THREADS_PER_INSTANCE = 50

    def __init__(self):
        self._processes = []
        self._ports = []
        self._counter = 0
        self._counter_lock = threading.Lock()
        self._pool_size = 1
        self._started = False

    @classmethod
    def get(cls):
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = cls()
        return cls._instance

    @classmethod
    def set_backend(cls, backend: str):
        if backend not in ("azuretls", "custom_tls", "okhttp_java"):
            raise ValueError(f"Unknown backend: {backend!r}")
        cls._backend = backend

    @classmethod
    def set_pool_size(cls, total_threads: int):
        mgr = cls.get()
        with cls._lock:
            needed = max(1, (total_threads + cls.THREADS_PER_INSTANCE - 1) // cls.THREADS_PER_INSTANCE)
            mgr._pool_size = needed

    @property
    def port(self):
        with self._lock:
            if not self._started:
                self._start_pool()
        if len(self._ports) == 1:
            return self._ports[0]
        with self._counter_lock:
            idx = self._counter % len(self._ports)
            self._counter += 1
        return self._ports[idx]

    def get_dedicated_port(self):
        return self.port

    @classmethod
    def _find_proxy_cmd(cls):
        import subprocess as _sp
        import shutil as _sh
        _candidates = []
        if getattr(sys, 'frozen', False):
            _exe_dir = os.path.dirname(sys.executable)
            _candidates.append(_exe_dir)
            _candidates.append(os.path.join(_exe_dir, "_internal"))
        _candidates.append(os.getcwd())
        _candidates.append(os.path.dirname(os.path.abspath(__file__)))
        _candidates.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
        base = None
        for _c in _candidates:
            if _c and os.path.exists(os.path.join(_c, "okhttp-proxy", "okhttp-proxy.jar")):
                base = _c
                break
        if base is None:
            base = os.getcwd()

        if cls._backend == "okhttp_java":
            jar_dir = os.path.join(base, "okhttp-proxy")
            jar_path = os.path.join(jar_dir, "okhttp-proxy.jar")
            libs_dir = os.path.join(jar_dir, "libs")
            if not os.path.exists(jar_path):
                raise RuntimeError(
                    f"okhttp-proxy.jar not found: {jar_path}\n"
                    f"Build: cd okhttp-proxy && python build.py")
            java_exe = None
            for _jdk_path in [
                r"C:\Program Files\Java\jdk-24\bin\java.exe",
                r"C:\Program Files\Java\jdk-21\bin\java.exe",
                r"C:\Program Files\Java\jdk-17\bin\java.exe",
                r"C:\Program Files\Java\jdk-11\bin\java.exe",
            ]:
                if os.path.exists(_jdk_path):
                    java_exe = _jdk_path
                    break
            if not java_exe:
                java_exe = _sh.which("java")
            if not java_exe:
                raise RuntimeError("Java not found. Install JDK 11+.")
            sep = ";" if sys.platform == "win32" else ":"
            cp = f"{jar_path}{sep}{libs_dir}/*"
            return [java_exe, "--enable-native-access=ALL-UNNAMED", "-cp", cp, "OkHttpProxy", "0"]

        if cls._backend == "custom_tls":
            sub_dir = "go-tls-client"
            bin_name = "go-tls-client"
        else:
            sub_dir = "go-proxy"
            bin_name = "go-proxy"

        exe_name = f"{bin_name}.exe" if sys.platform == "win32" else bin_name
        go_bin = os.path.join(base, sub_dir, exe_name)

        if not os.path.exists(go_bin):
            go_dir = os.path.join(base, sub_dir)
            if os.path.exists(os.path.join(go_dir, "go.mod")):
                go_exe = _sh.which("go")
                if go_exe:
                    print(f"[proxy] Building {sub_dir} (first time only)...")
                    r = _sp.run(
                        [go_exe, "build", "-o", exe_name, "."],
                        capture_output=True, text=True, cwd=go_dir,
                    )
                    if r.returncode != 0:
                        raise RuntimeError(f"Failed to build {sub_dir}:\n{r.stdout}\n{r.stderr}")
                else:
                    raise RuntimeError("Go not found in PATH. Install Go 1.24+.")

        if not os.path.exists(go_bin):
            raise RuntimeError(f"Go proxy binary not found: {go_bin}")
        return [go_bin, "0"]

    def _start_one(self, cmd: list) -> int:
        import subprocess as _sp
        env = dict(os.environ)
        env["DEBUG_PROXY"] = "1"
        proc = _sp.Popen(cmd, stdout=_sp.PIPE, stderr=_sp.PIPE, text=True, env=env)
        self._processes.append(proc)

        port = None
        tls_line = proc.stdout.readline().strip()
        if tls_line.startswith("TLS:"):
            tls_provider = tls_line.split(":")[1]
            if len(self._processes) == 1:
                print(f"[proxy] TLS provider: {tls_provider}")
        elif tls_line.startswith("PORT:"):
            port = int(tls_line.split(":")[1])
        else:
            err = proc.stderr.read()
            raise RuntimeError(f"Proxy start failed: {tls_line}\n{err}")

        if port is None:
            port_line = proc.stdout.readline().strip()
            if not port_line.startswith("PORT:"):
                err = proc.stderr.read()
                raise RuntimeError(f"Proxy start failed: {port_line}\n{err}")
            port = int(port_line.split(":")[1])

        def _drain(p, idx):
            try:
                for line in p.stderr:
                    line = line.strip()
                    if line:
                        if "[ws" in line or "[req]" in line:
                            if _DEBUG:
                                print(f"\033[90m[proxy-{idx}]\033[0m {line}")
                        else:
                            print(f"[proxy-{idx}-err] {line}")
            except Exception:
                pass
        threading.Thread(target=_drain, args=(proc, len(self._processes)), daemon=True).start()
        return port

    def _start_pool(self):
        import atexit
        cmd = self._find_proxy_cmd()
        for i in range(self._pool_size):
            port = self._start_one(cmd)
            self._ports.append(port)
        self._started = True
        labels = {"azuretls": "Go azuretls", "custom_tls": "Go custom-utls", "okhttp_java": "Java OkHttp+Conscrypt"}
        label = labels.get(self._backend, self._backend)
        if self._pool_size == 1:
            print(f"[proxy] {label} proxy on port {self._ports[0]}")
        else:
            print(f"[proxy] {label} proxy pool: {self._pool_size} instances on ports {self._ports}")
        atexit.register(self._stop_all)

    def spawn_isolated(self) -> tuple:
        cmd = self._find_proxy_cmd()
        import subprocess as _sp
        proc = _sp.Popen(cmd, stdout=_sp.PIPE, stderr=_sp.PIPE, text=True)
        port = None
        line1 = proc.stdout.readline().strip()
        if line1.startswith("TLS:"):
            pass
        elif line1.startswith("PORT:"):
            port = int(line1.split(":")[1])
        else:
            proc.kill()
            return None, None
        if port is None:
            line2 = proc.stdout.readline().strip()
            if line2.startswith("PORT:"):
                port = int(line2.split(":")[1])
            else:
                proc.kill()
                return None, None
        threading.Thread(target=lambda p: [None for _ in p.stderr], args=(proc,), daemon=True).start()
        return port, proc

    @staticmethod
    def kill_isolated(proc):
        if proc:
            try:
                proc.terminate()
                proc.wait(timeout=3)
            except Exception:
                try:
                    proc.kill()
                except Exception:
                    pass

    def clear_session(self, proxy_raw: str = None, port: int = None):
        target_port = port or (self._ports[0] if self._ports else None)
        if not target_port:
            return
        import urllib.request as _ur
        payload = _json_module.dumps({"all": True}).encode() if proxy_raw is None else \
            _json_module.dumps({
                "proxy": {
                    "host": proxy_raw.split(":")[0] if proxy_raw else "",
                    "port": int(proxy_raw.split(":")[1]) if proxy_raw and ":" in proxy_raw else 0,
                },
                "tls_profile": "conscrypt",
            }).encode()
        try:
            req = _ur.Request(
                f"http://127.0.0.1:{target_port}/session/clear",
                data=payload,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            _ur.urlopen(req, timeout=5)
        except Exception:
            pass

    def clear_all_sessions(self):
        import urllib.request as _ur
        payload = _json_module.dumps({"all": True}).encode()
        for p in self._ports:
            try:
                req = _ur.Request(
                    f"http://127.0.0.1:{p}/session/clear",
                    data=payload, headers={"Content-Type": "application/json"}, method="POST",
                )
                _ur.urlopen(req, timeout=5)
            except Exception:
                pass

    def _stop_all(self):
        for proc in self._processes:
            if proc:
                proc.terminate()
                try:
                    proc.wait(timeout=5)
                except Exception:
                    proc.kill()
        self._processes.clear()
        self._ports.clear()
        self._started = False


class _OkHttpSession:

    def __init__(self, proxy_url=None, tls_profile="conscrypt", port_override=None):
        self._default_proxy = proxy_url
        self._cookie_str = ""
        self._tls_profile = tls_profile
        if port_override:
            self._port = port_override
            self._mgr = None
        else:
            self._mgr = _OkHttpProxyManager.get()
            self._port = self._mgr.get_dedicated_port()

    @property
    def cookies(self):
        return self

    def set(self, name, value, domain=None):
        if self._cookie_str:
            parts = [p.strip() for p in self._cookie_str.split(";")]
            for i, part in enumerate(parts):
                if "=" in part and part.split("=", 1)[0].strip() == name:
                    parts[i] = f"{name}={value}"
                    self._cookie_str = "; ".join(parts)
                    return
            self._cookie_str += f"; {name}={value}"
        else:
            self._cookie_str = f"{name}={value}"

    def items(self):
        if not self._cookie_str:
            return []
        result = []
        for part in self._cookie_str.split(";"):
            part = part.strip()
            if "=" in part:
                n, v = part.split("=", 1)
                result.append((n.strip(), v.strip()))
        return result

    def clear(self):
        self._cookie_str = ""

    def __bool__(self):
        return bool(self._cookie_str)

    def __iter__(self):
        for n, v in self.items():
            yield type("Cookie", (), {"name": n, "value": v, "domain": ".discord.com", "path": "/"})()

    def _inject_cookies(self, headers):
        if not self._cookie_str:
            return headers
        h = dict(headers) if headers else {}
        if "Cookie" not in h and "cookie" not in h:
            h["Cookie"] = self._cookie_str
        return h

    def _absorb_cookies(self, resp):
        if not hasattr(resp, "_set_cookies"):
            return resp
        for raw in resp._set_cookies:
            try:
                nv = raw.split(";", 1)[0].strip()
                if "=" in nv:
                    n, v = nv.split("=", 1)
                    self.set(n.strip(), v.strip())
            except Exception:
                pass
        return resp

    @staticmethod
    def _parse_proxy(proxy_url):
        if not proxy_url:
            return None
        p = urlparse(proxy_url)
        return {
            "type": (p.scheme or "http").replace("https", "http"),
            "host": p.hostname,
            "port": p.port,
            "user": p.username,
            "pass": p.password,
        }

    def _request(self, method, url, headers=None, body=None,
                 proxy=None, timeout=30, max_redirects=None):
        h = self._inject_cookies(headers)
        header_pairs = [[k, v] for k, v in h.items()] if h else []
        proxy_obj = self._parse_proxy(proxy or self._default_proxy)

        req_json = {
            "method": method,
            "url": url,
            "headers": header_pairs,
            "proxy": proxy_obj,
            "timeout": timeout,
            "tls_profile": self._tls_profile,
        }
        if max_redirects is not None:
            req_json["max_redirects"] = max_redirects
        if isinstance(body, (bytes, bytearray)):
            import base64 as _b64
            req_json["body_b64"] = _b64.b64encode(body).decode()
        else:
            req_json["body"] = body
        payload = _json_module.dumps(req_json, separators=(",", ":")).encode()

        import urllib.request as _ur
        import urllib.error as _ue

        ports_to_try = [self._port]
        if self._mgr and hasattr(self._mgr, '_ports'):
            for p in self._mgr._ports:
                if p != self._port and p not in ports_to_try:
                    ports_to_try.append(p)

        last_err = None
        for port in ports_to_try:
            req = _ur.Request(
                f"http://127.0.0.1:{port}/req",
                data=payload,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            try:
                with _ur.urlopen(req, timeout=timeout + 15) as r:
                    result = _json_module.loads(r.read().decode())
                if port != self._port:
                    self._port = port
                last_err = None
                break
            except (_ue.URLError, ConnectionError, OSError) as e:
                last_err = e
                continue
            except Exception as e:
                raise ConnectionError(f"OkHttp proxy: {e}") from e

        if last_err is not None:
            raise ConnectionError(f"OkHttp proxy: {last_err}") from last_err

        if "error" in result:
            raise ConnectionError(f"OkHttp: {result['error']}")

        return self._absorb_cookies(_OkHttpResponse(result))

    def get(self, url, headers=None, params=None,
            proxy=None, timeout_seconds=30, **kw):
        if params:
            sep = "&" if "?" in url else "?"
            url = url + sep + urlencode(params)
        return self._request("GET", url, headers, None, proxy, timeout_seconds,
                             max_redirects=kw.get("max_redirects"))

    def post(self, url, headers=None, json=None, data=None,
             proxy=None, timeout_seconds=30, **kw):
        if json is not None and data is None:
            data = _json_module.dumps(json, separators=(",", ":"))
            headers = dict(headers) if headers else {}
            headers.setdefault("Content-Type", "application/json")
        return self._request("POST", url, headers, data, proxy, timeout_seconds)

    def patch(self, url, headers=None, json=None, data=None,
              proxy=None, timeout_seconds=30, **kw):
        if json is not None and data is None:
            data = _json_module.dumps(json, separators=(",", ":"))
            headers = dict(headers) if headers else {}
            headers.setdefault("Content-Type", "application/json")
        return self._request("PATCH", url, headers, data, proxy, timeout_seconds)

    def put(self, url, headers=None, json=None, data=None,
            proxy=None, timeout_seconds=30, **kw):
        if json is not None and data is None:
            data = _json_module.dumps(json, separators=(",", ":"))
            headers = dict(headers) if headers else {}
            headers.setdefault("Content-Type", "application/json")
        return self._request("PUT", url, headers, data, proxy, timeout_seconds)

    def delete(self, url, headers=None,
               proxy=None, timeout_seconds=30, **kw):
        return self._request("DELETE", url, headers, None, proxy, timeout_seconds)
