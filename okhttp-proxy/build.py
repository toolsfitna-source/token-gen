#!/usr/bin/env python3
"""
Download OkHttp 4.11.0 + deps from Maven Central, compile OkHttpProxy.java,
and package everything into a single fat JAR (okhttp-proxy.jar).

Requirements: JDK 11+  (javac + jar on PATH)
Usage:        python build.py
"""
import os
import sys
import shutil
import subprocess
import zipfile
import urllib.request

DEPS = {
    "okhttp-4.11.0.jar":
        "https://repo1.maven.org/maven2/com/squareup/okhttp3/okhttp/4.11.0/okhttp-4.11.0.jar",
    "okio-jvm-3.4.0.jar":
        "https://repo1.maven.org/maven2/com/squareup/okio/okio-jvm/3.4.0/okio-jvm-3.4.0.jar",
    "kotlin-stdlib-1.8.21.jar":
        "https://repo1.maven.org/maven2/org/jetbrains/kotlin/kotlin-stdlib/1.8.21/kotlin-stdlib-1.8.21.jar",
    "gson-2.10.1.jar":
        "https://repo1.maven.org/maven2/com/google/code/gson/gson/2.10.1/gson-2.10.1.jar",
    # Conscrypt: BoringSSL provider — makes TLS fingerprint match real Android
    # (Android uses BoringSSL via Conscrypt, desktop Java uses SunJSSE — different JA3/JA4)
    "conscrypt-openjdk-uber-2.5.2.jar":
        "https://repo1.maven.org/maven2/org/conscrypt/conscrypt-openjdk-uber/2.5.2/conscrypt-openjdk-uber-2.5.2.jar",
}

def main():
    base = os.path.dirname(os.path.abspath(__file__))
    libs = os.path.join(base, "libs")
    os.makedirs(libs, exist_ok=True)

    # 1) Download dependencies
    print("[build] Downloading dependencies...")
    for name, url in DEPS.items():
        path = os.path.join(libs, name)
        if os.path.exists(path):
            print(f"  [ok]  {name}")
            continue
        print(f"  [dl]  {name} ...")
        urllib.request.urlretrieve(url, path)
        print(f"  [ok]  {name}")

    # 2) Check javac
    javac = shutil.which("javac")
    if not javac:
        print("\nERROR: javac not found.  Install JDK 11+ and add it to PATH.")
        print("  Windows:  winget install EclipseAdoptium.Temurin.21.JDK")
        print("  Or:       https://adoptium.net/")
        sys.exit(1)

    # 3) Compile
    sep = ";" if sys.platform == "win32" else ":"
    cp = sep.join(os.path.join(libs, j) for j in DEPS)
    src = os.path.join(base, "src", "main", "java", "OkHttpProxy.java")
    out_dir = os.path.join(base, "build")
    os.makedirs(out_dir, exist_ok=True)

    print("[build] Compiling OkHttpProxy.java ...")
    r = subprocess.run(
        [javac, "-cp", cp, "-d", out_dir, src],
        capture_output=True, text=True,
    )
    if r.returncode != 0:
        print(f"Compile error:\n{r.stderr}")
        sys.exit(1)
    print("  [ok]  compiled")

    # 4) Create fat JAR
    jar_path = os.path.join(base, "okhttp-proxy.jar")
    print(f"[build] Packaging {jar_path} ...")
    seen = {"META-INF/", "META-INF/MANIFEST.MF"}

    with zipfile.ZipFile(jar_path, "w", zipfile.ZIP_DEFLATED) as zf:
        # Manifest
        zf.writestr("META-INF/MANIFEST.MF",
                     "Manifest-Version: 1.0\nMain-Class: OkHttpProxy\n")

        # Compiled classes
        for root, _, files in os.walk(out_dir):
            for f in files:
                if not f.endswith(".class"):
                    continue
                full = os.path.join(root, f)
                arc = os.path.relpath(full, out_dir).replace("\\", "/")
                if arc not in seen:
                    zf.write(full, arc)
                    seen.add(arc)

        # Merge dependency JARs (skip their META-INF, except native libs)
        for jar_name in DEPS:
            dep_path = os.path.join(libs, jar_name)
            with zipfile.ZipFile(dep_path) as dep:
                for info in dep.infolist():
                    name = info.filename
                    if info.is_dir():
                        continue
                    # Keep META-INF/native/ (Conscrypt native libs) but skip other META-INF
                    if name.startswith("META-INF/") and not name.startswith("META-INF/native/"):
                        continue
                    if name in seen:
                        continue
                    zf.writestr(info, dep.read(name))
                    seen.add(name)

    size_mb = os.path.getsize(jar_path) / (1024 * 1024)
    print(f"  [ok]  {jar_path}  ({size_mb:.1f} MB)")
    print("[build] Done!  Run with:  java -jar okhttp-proxy.jar")


if __name__ == "__main__":
    main()
