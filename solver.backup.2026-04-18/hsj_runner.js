/**
 * HSJ Runner — executes hsj(jwt) in a VM sandbox with crypto.subtle hooks
 * to intercept the AES-256-GCM key used for N payload encryption.
 *
 * Usage:  node hsj_runner.js <jwt> <path_to_hsj.js>
 * Output: JSON on stdout  { "key_hex": "..." }
 *         or               { "error": "..." }
 *
 * Based on the proven extract_aes_key_hook.js approach (VM + crypto hooks).
 */

const { TextEncoder, TextDecoder } = require("util");
const vm = require("vm");
const { webcrypto } = require("crypto");
const fs = require("fs");
const path = require("path");

const jwt = process.argv[2];
const hsjPath = process.argv[3];
const profilePath = process.argv[4] || null;

if (!jwt || !hsjPath) {
    process.stdout.write(JSON.stringify({ error: "Usage: node hsj_runner.js <jwt> <hsj.js> [profile.json]" }));
    process.exit(1);
}
if (!fs.existsSync(hsjPath)) {
    process.stdout.write(JSON.stringify({ error: `hsj.js not found: ${hsjPath}` }));
    process.exit(1);
}

// Load phone HSJ profile if provided — used to override the sandbox's
// navigator/screen/href so the generated N matches the phone fingerprint.
let phoneProfile = null;
if (profilePath && fs.existsSync(profilePath)) {
    try {
        phoneProfile = JSON.parse(fs.readFileSync(profilePath, "utf-8"));
        process.stderr.write(`[hsj_runner] Loaded phone profile: ${path.basename(profilePath)}\n`);
    } catch (e) {
        process.stderr.write(`[hsj_runner] Failed to parse profile: ${e.message}\n`);
    }
}

// ── Captured data ──
let capturedKeyHex = null;
let capturedPlaintext = null;

// ── Hook crypto.subtle to intercept AES key ──
const hookedCrypto = {
    subtle: {
        importKey: async (format, keyData, algorithm, extractable, keyUsages) => {
            const keyBytes = new Uint8Array(keyData instanceof ArrayBuffer ? keyData : keyData.buffer || keyData);
            const keyHex = Buffer.from(keyBytes).toString("hex");
            const algoName = typeof algorithm === "string" ? algorithm : algorithm?.name || "unknown";

            if ((algoName.includes("GCM") || algoName.includes("AES")) && keyBytes.length === 32) {
                capturedKeyHex = keyHex;
                process.stderr.write(`[hsj_runner] AES key captured: ${keyHex.substring(0, 16)}...\n`);
            }
            return webcrypto.subtle.importKey(format, keyData, algorithm, true, keyUsages);
        },
        encrypt: async (algorithm, key, data) => {
            const plainBytes = new Uint8Array(data instanceof ArrayBuffer ? data : data.buffer || data);
            try {
                const str = new TextDecoder().decode(plainBytes);
                if (str.startsWith("[[")) {
                    capturedPlaintext = str;
                    // Try to export key if not captured yet
                    if (!capturedKeyHex) {
                        try {
                            const exported = await webcrypto.subtle.exportKey("raw", key);
                            capturedKeyHex = Buffer.from(new Uint8Array(exported)).toString("hex");
                        } catch (e) {}
                    }
                }
            } catch (e) {}
            return webcrypto.subtle.encrypt(algorithm, key, data);
        },
        decrypt: async (...args) => webcrypto.subtle.decrypt(...args),
        generateKey: (...args) => webcrypto.subtle.generateKey(...args),
        exportKey: (...args) => webcrypto.subtle.exportKey(...args),
        deriveBits: (...args) => webcrypto.subtle.deriveBits(...args),
        deriveKey: (...args) => webcrypto.subtle.deriveKey(...args),
        sign: (...args) => webcrypto.subtle.sign(...args),
        verify: (...args) => webcrypto.subtle.verify(...args),
        digest: (...args) => webcrypto.subtle.digest(...args),
        wrapKey: (...args) => webcrypto.subtle.wrapKey(...args),
        unwrapKey: (...args) => webcrypto.subtle.unwrapKey(...args),
    },
    getRandomValues: (arr) => webcrypto.getRandomValues(arr),
    randomUUID: () => webcrypto.randomUUID(),
};

// ── Canvas stub ──
let createCanvas;
try { createCanvas = require("canvas").createCanvas; } catch (e) {
    createCanvas = (w, h) => ({
        width: w, height: h,
        getContext() {
            return new Proxy({}, {
                get(_, p) { if (typeof p === "symbol") return undefined; return function () { return this; }; },
                set() { return true; },
            });
        },
        toDataURL() { return "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8/5+hHgAHggJ/PchI7wAAAABJRU5ErkJggg=="; },
    });
}

// ── WebGL stub ──
const fakeGLCtx = new Proxy({}, {
    get(_, p) {
        if (typeof p === "symbol") return undefined;
        if (p === "getExtension") return (name) => name === "WEBGL_debug_renderer_info" ? { UNMASKED_VENDOR_WEBGL: 37445, UNMASKED_RENDERER_WEBGL: 37446 } : null;
        if (p === "getParameter") return (x) => {
            if (x === 37446) return "Adreno (TM) 720";
            if (x === 37445) return "Qualcomm";
            if (x === 7938) return "WebGL 2.0 (OpenGL ES 3.0 Chromium)";
            if (x === 35724) return "WebGL GLSL ES 3.00 (OpenGL ES GLSL ES 3.0 Chromium)";
            if (x === 7936) return "WebKit";
            if (x === 7937) return "WebKit WebGL";
            if (x === 3379) return 8192;
            if (x === 34024) return 16384;
            if (x === 3386) return new Int32Array([16384, 16384]);
            if (x === 3408) return new Float32Array([1, 1023]);
            if (x === 3414) return new Float32Array([1, 8]);
            return null;
        };
        if (p === "getSupportedExtensions") return () => ["EXT_color_buffer_float", "WEBGL_multi_draw", "WEBGL_debug_renderer_info"];
        if (p === "canvas") return createCanvas(300, 150);
        if (p === "readPixels") return (x, y, w, h, f, t, px) => { if (px) px.fill(128); };
        const c = { VERTEX_SHADER: 35633, FRAGMENT_SHADER: 35632, COMPILE_STATUS: 35713, LINK_STATUS: 35714, RGBA: 6408, UNSIGNED_BYTE: 5121 };
        if (p in c) return c[p];
        return function () { return null; };
    },
    set() { return true; },
});

// ── VM Sandbox (comprehensive browser mock) ──
const sandbox = {
    console: { log() {}, warn() {}, info() {}, debug() {}, dir() {}, trace() {}, error: (...a) => process.stderr.write(`[hsj] ${a.join(" ")}\n`) },
    setTimeout, clearTimeout, setInterval, clearInterval, setImmediate, clearImmediate,
    Promise, Proxy, Reflect, Symbol, Map, Set, WeakMap, WeakSet,
    Array, Object, String, Number, Boolean, RegExp, Date, Math, JSON, Error,
    TypeError, RangeError, ReferenceError, SyntaxError, URIError, EvalError,
    Int8Array, Uint8Array, Uint8ClampedArray, Int16Array, Uint16Array,
    Int32Array, Uint32Array, Float32Array, Float64Array, BigInt64Array, BigUint64Array,
    ArrayBuffer, SharedArrayBuffer, DataView, BigInt,
    TextEncoder, TextDecoder, WebAssembly, URL, URLSearchParams,
    Intl: typeof Intl !== "undefined" ? Intl : undefined,
    atob: (s) => Buffer.from(s, "base64").toString("binary"),
    btoa: (s) => Buffer.from(s, "binary").toString("base64"),
    crypto: hookedCrypto,
    performance: {
        now: () => performance.now(),
        timing: { navigationStart: Date.now() - 3000 },
        getEntriesByType: () => [],
    },
    queueMicrotask,
    structuredClone: globalThis.structuredClone,
    fetch: () => Promise.resolve({
        ok: true, status: 200,
        json: () => Promise.resolve({}),
        text: () => Promise.resolve(""),
        arrayBuffer: () => Promise.resolve(new ArrayBuffer(0)),
    }),
    document: {
        createElement(tag) {
            if (tag === "canvas") {
                const c = createCanvas(300, 150);
                const orig = c.getContext.bind(c);
                c.getContext = function (type) {
                    return (type === "webgl" || type === "webgl2") ? fakeGLCtx : orig(type);
                };
                return c;
            }
            return {
                tagName: tag.toUpperCase(), style: {},
                setAttribute() {}, getAttribute() { return null; }, hasAttribute() { return false; },
                appendChild() { return this; }, removeChild() { return this; },
                addEventListener() {}, innerHTML: "", textContent: "",
                getElementsByTagName() { return []; }, querySelector() { return null; },
                querySelectorAll() { return []; }, childNodes: [], children: [],
                getBoundingClientRect() { return { top: 0, left: 0, width: 0, height: 0 }; },
                canPlayType: (t) => t.includes("webm") ? "probably" : "",
            };
        },
        createElementNS(ns, tag) { return this.createElement(tag); },
        querySelector() { return null; }, querySelectorAll() { return []; },
        getElementById() { return null; }, getElementsByTagName() { return []; },
        getElementsByClassName() { return []; },
        documentElement: {
            style: {}, getAttribute() { return null; }, hasAttribute() { return false; },
            setAttribute() {}, classList: { add() {}, remove() {}, contains() { return false; } },
        },
        body: { appendChild() { return this; }, removeChild() { return this; }, style: {}, hasAttribute() { return false; }, getAttribute() { return null; } },
        head: { appendChild() { return this; } },
        cookie: "", readyState: "complete", hidden: false, visibilityState: "visible",
        referrer: "", title: "", scripts: [], styleSheets: [], name: "",
        hasFocus() { return true; }, addEventListener() {}, removeEventListener() {},
        createEvent() { return { initEvent() {} }; },
        createDocumentFragment() { return { appendChild() { return this; }, childNodes: [] }; },
        createTextNode(t) { return { textContent: t }; },
    },
    location: {
        href: "https://newassets.hcaptcha.com/captcha/v1/stub/hcaptcha.html",
        hostname: "newassets.hcaptcha.com",
        origin: "https://newassets.hcaptcha.com",
        protocol: "https:",
        pathname: "/captcha/v1/stub/hcaptcha.html",
        reload() {},
    },
    navigator: {
        userAgent: "Mozilla/5.0 (Linux; Android 14; Pixel 8 Build/AP2A.240305.019.A1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.6943.137 Mobile Safari/537.36",
        appVersion: "5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36",
        appName: "Netscape", appCodeName: "Mozilla", product: "Gecko", productSub: "20030107",
        language: "en-US", languages: ["en-US", "en"], platform: "Linux armv81",
        vendor: "Google Inc.", vendorSub: "", maxTouchPoints: 5, hardwareConcurrency: 8, deviceMemory: 8,
        webdriver: false, cookieEnabled: true, onLine: true, doNotTrack: null, pdfViewerEnabled: false,
        plugins: { length: 0 }, mimeTypes: { length: 0 },
        connection: { effectiveType: "4g", downlink: 10, rtt: 100, type: "cellular", saveData: false },
        permissions: { query: () => Promise.resolve({ state: "prompt", addEventListener() {} }) },
        mediaDevices: { enumerateDevices: () => Promise.resolve([]) },
        getBattery: () => Promise.resolve({ charging: true, level: 1, addEventListener() {} }),
        getGamepads: () => [], javaEnabled: () => false, vibrate: () => true, sendBeacon: () => true,
        userAgentData: {
            brands: [{ brand: "Chromium", version: "133" }, { brand: "Not-A.Brand", version: "24" }],
            mobile: true, platform: "Android",
            getHighEntropyValues: () => Promise.resolve({
                platform: "Android", platformVersion: "14.0.0", architecture: "",
                model: "Pixel 8", uaFullVersion: "133.0.6943.137",
                fullVersionList: [{ brand: "Chromium", version: "133.0.6943.137" }],
                formFactors: ["Mobile"],
            }),
        },
        clipboard: { readText: () => Promise.resolve(""), writeText: () => Promise.resolve() },
        keyboard: {}, locks: { request: () => Promise.resolve() },
        storage: { estimate: () => Promise.resolve({ quota: 1e9, usage: 1e6 }) },
        serviceWorker: { controller: null },
        credentials: { get: () => Promise.resolve(null) },
        mediaCapabilities: { decodingInfo: () => Promise.resolve({ supported: true, smooth: true, powerEfficient: true }) },
        webkitTemporaryStorage: { queryUsageAndQuota: (s) => s?.(1e6, 1e9) },
        [Symbol.toStringTag]: "Navigator",
    },
    screen: {
        width: 435, height: 965, availWidth: 435, availHeight: 965,
        availLeft: 0, availTop: 0, colorDepth: 24, pixelDepth: 24,
        orientation: { type: "portrait-primary", angle: 0, addEventListener() {} },
        [Symbol.toStringTag]: "Screen",
    },
    innerWidth: 457, innerHeight: 908, outerWidth: 435, outerHeight: 965,
    devicePixelRatio: 2.625, screenX: 0, screenY: 0,
    pageXOffset: 0, pageYOffset: 0, scrollX: 0, scrollY: 0,
    visualViewport: { width: 457, height: 908, offsetLeft: 0, offsetTop: 0, pageLeft: 0, pageTop: 0, scale: 1, addEventListener() {} },
    speechSynthesis: { getVoices: () => [], speak() {}, cancel() {}, pause() {}, resume() {}, addEventListener() {} },
    AudioContext: class {
        constructor() { this.state = "running"; this.sampleRate = 48000; }
        createOscillator() { return { connect() {}, start() {}, type: "sine", frequency: { value: 440 } }; }
        createAnalyser() { return { connect() {}, fftSize: 2048, getFloatFrequencyData: (a) => a?.fill?.(-100) }; }
        createDynamicsCompressor() { return { connect() {}, threshold: { value: -50 }, knee: { value: 40 }, ratio: { value: 12 }, attack: { value: 0 }, release: { value: 0.25 } }; }
        createGain() { return { connect() {}, gain: { value: 1 } }; }
        createBiquadFilter() { return { connect() {}, type: "lowpass", frequency: { value: 350 }, Q: { value: 1 } }; }
        createScriptProcessor() { return { connect() {}, disconnect() {}, onaudioprocess: null }; }
        createBufferSource() { return { connect() {}, start() {}, buffer: null }; }
        get destination() { return {}; }
        close() { return Promise.resolve(); }
    },
    OfflineAudioContext: class {
        constructor(ch, len) { this.length = len || 44100; }
        createOscillator() { return { connect() {}, start() {}, type: "sine", frequency: { value: 440 } }; }
        createDynamicsCompressor() { return { connect() {}, threshold: { value: -50 }, knee: { value: 40 }, ratio: { value: 12 }, attack: { value: 0 }, release: { value: 0.25 } }; }
        createGain() { return { connect() {}, gain: { value: 1 } }; }
        get destination() { return {}; }
        startRendering() { return Promise.resolve({ getChannelData: () => new Float32Array(this.length) }); }
    },
    RTCPeerConnection: class { createDataChannel() { return {}; } createOffer() { return Promise.resolve({ sdp: "v=0\r\n" }); } close() {} addEventListener() {} },
    requestAnimationFrame: (cb) => setTimeout(cb, 16),
    cancelAnimationFrame: clearTimeout,
    addEventListener() {}, removeEventListener() {}, dispatchEvent() { return true; }, postMessage() {},
    onerror: null, onunhandledrejection: null,
};

// Wire up self-references
sandbox.self = sandbox;
sandbox.window = sandbox;
sandbox.globalThis = sandbox;
sandbox.top = sandbox;
sandbox.parent = sandbox;
sandbox.frames = sandbox;
sandbox.document.defaultView = sandbox;
sandbox.document.location = sandbox.location;
sandbox.Window = function () { throw new TypeError("Illegal constructor"); };
Object.defineProperty(sandbox, Symbol.toStringTag, { value: "Window" });

// ── Apply phone profile overrides (before VM context is finalized) ──
if (phoneProfile) {
    try {
        const comps = phoneProfile.components || {};
        const pNav = comps.navigator || {};
        const pScr = comps.screen || {};

        // Navigator: merge phone-authentic fields over the default sandbox nav
        const navOverrides = {
            userAgent: pNav.user_agent,
            appVersion: pNav.app_version,
            platform: pNav.platform,
            language: pNav.language,
            languages: pNav.languages,
            vendor: pNav.vendor,
            vendorSub: pNav.vendor_sub,
            product: pNav.product,
            productSub: pNav.product_sub,
            hardwareConcurrency: pNav.hardware_concurrency,
            deviceMemory: pNav.device_memory,
            maxTouchPoints: pNav.max_touch_points,
            cookieEnabled: pNav.cookie_enabled,
            onLine: pNav.on_line,
            doNotTrack: pNav.do_not_track,
            pdfViewerEnabled: pNav.pdf_viewer_enabled,
            webdriver: pNav.webdriver,
        };
        for (const [k, v] of Object.entries(navOverrides)) {
            if (v !== undefined && v !== null) sandbox.navigator[k] = v;
        }

        // userAgentData high-entropy override from phone UA family
        if (pNav.user_agent_data) {
            sandbox.navigator.userAgentData = Object.assign(
                sandbox.navigator.userAgentData || {}, pNav.user_agent_data
            );
        }

        // Screen: full override
        if (pScr.width) sandbox.screen.width = pScr.width;
        if (pScr.height) sandbox.screen.height = pScr.height;
        if (pScr.avail_width) sandbox.screen.availWidth = pScr.avail_width;
        if (pScr.avail_height) sandbox.screen.availHeight = pScr.avail_height;
        if (pScr.color_depth) sandbox.screen.colorDepth = pScr.color_depth;
        if (pScr.pixel_depth) sandbox.screen.pixelDepth = pScr.pixel_depth;

        // devicePixelRatio at window level
        if (comps.device_pixel_ratio) {
            sandbox.devicePixelRatio = comps.device_pixel_ratio;
        }

        // href: the URL the captcha WebView was loaded at
        const href = phoneProfile.href;
        if (href) {
            sandbox.location.href = href;
            try {
                const u = new URL(href.startsWith("data:") ? "https://newassets.hcaptcha.com/captcha/v1/stub" : href);
                sandbox.location.hostname = u.hostname;
                sandbox.location.origin = u.origin;
                sandbox.location.protocol = u.protocol;
                sandbox.location.pathname = u.pathname;
            } catch (e) {}
        }

        process.stderr.write(`[hsj_runner] Applied profile: UA=${String(sandbox.navigator.userAgent).substring(0, 60)}... screen=${sandbox.screen.width}x${sandbox.screen.height} dpr=${sandbox.devicePixelRatio}\n`);
    } catch (e) {
        process.stderr.write(`[hsj_runner] Profile apply error: ${e.message}\n`);
    }
}

// ── Create VM context ──
const context = vm.createContext(sandbox);
sandbox.eval = vm.runInContext("eval", context);
sandbox.Function = vm.runInContext("Function", context);

// ── Load and patch HSJ ──
let hsjCode = fs.readFileSync(hsjPath, "utf-8");

// Patch the "instanceof Window" check that crashes in Node
hsjCode = hsjCode.replace(
    /(\w+)\s*:\s*function\s*\((\w+)\)\s*\{var\s+(\w+);try\{\3=\w+\(\2\)\s*instanceof\s+Window\}catch\(\w+\)\{\3=!1\}return\s+\3\}/,
    "$1:function(){return true}"
);

// ── HEAP8 hooking: intercept WASM Int8Array creation to read AES key ──
// HSJ uses internal WASM AES — key lives at HEAP8[1046256] (not crypto.subtle)
const KEY_ADDR = 1046256;
const HEAP_PATTERNS = [
    "r = new Int8Array(e)",
    "r = new Int8Array(k)",
];
for (const pat of HEAP_PATTERNS) {
    if (hsjCode.includes(pat)) {
        // Expose HEAP8 on self so we can read it after hsj() runs
        // e.g. "r = new Int8Array(e)" → "r = (self.__HEAP8__ = new Int8Array(e))"
        const varName = pat.split("=")[0].trim(); // "r"
        const arg = pat.match(/Int8Array\((\w+)\)/)[1]; // "e" or "k"
        const replacement = `${varName} = (self.__HEAP8__ = new Int8Array(${arg}))`;
        hsjCode = hsjCode.replace(pat, replacement);
        process.stderr.write(`[hsj_runner] Patched HEAP8 creation: ${pat} → ${replacement}\n`);
        break;
    }
}

process.stderr.write("[hsj_runner] Loading hsj.js into VM sandbox...\n");

try {
    vm.runInContext(hsjCode, context, { filename: "hsj.js", timeout: 30000 });
} catch (e) {
    if (!context.hsj) {
        process.stdout.write(JSON.stringify({ error: `hsj.js failed to load: ${e.message}` }));
        process.exit(1);
    }
    process.stderr.write(`[hsj_runner] eval warning (non-fatal): ${e.message}\n`);
}

if (typeof context.hsj !== "function") {
    process.stdout.write(JSON.stringify({ error: "hsj function not defined after eval" }));
    process.exit(1);
}

process.stderr.write("[hsj_runner] hsj loaded, calling hsj(jwt)...\n");

function extractKeyFromHeap() {
    const heap = sandbox.__HEAP8__;
    if (!heap) return null;
    let allZero = true;
    for (let i = 0; i < 32; i++) {
        if (heap[KEY_ADDR + i] !== 0) { allZero = false; break; }
    }
    if (allZero) return null;
    let hex = "";
    const bytes = [];
    for (let i = 0; i < 32; i++) {
        let b = heap[KEY_ADDR + i];
        if (b < 0) b += 256;
        bytes.push(b);
        hex += b.toString(16).padStart(2, "0");
    }
    return hex;
}

// ── Execute hsj(jwt) and extract key from HEAP8 ──
(async () => {
    try {
        const result = await context.hsj(jwt);
        process.stderr.write(`[hsj_runner] hsj() returned: ${result ? result.length + " chars" : "null"}\n`);

        // Try crypto.subtle captured key first
        if (capturedKeyHex) {
            process.stdout.write(JSON.stringify({
                key_hex: capturedKeyHex,
                n_token: result || null,
                source: "crypto_subtle",
            }));
            process.exit(0);
        }

        // Try HEAP8 extraction
        const heapKey = extractKeyFromHeap();
        if (heapKey) {
            process.stderr.write(`[hsj_runner] Key extracted from HEAP8[${KEY_ADDR}]: ${heapKey.substring(0, 16)}...\n`);
            process.stdout.write(JSON.stringify({
                key_hex: heapKey,
                n_token: result || null,
                source: "heap8",
            }));
            process.exit(0);
        }

        // If hsj returned an N token, the encryption already happened internally.
        // The N token IS the encrypted result — we need to capture the key BEFORE
        // encryption. Try polling HEAP8 briefly (key may still be in memory).
        if (result) {
            let attempts = 0;
            const poll = setInterval(() => {
                attempts++;
                const k = extractKeyFromHeap();
                if (k) {
                    clearInterval(poll);
                    process.stdout.write(JSON.stringify({ key_hex: k, n_token: result, source: "heap8_poll" }));
                    process.exit(0);
                }
                if (attempts >= 5) {
                    clearInterval(poll);
                    // Return the N token even without the key — the solver can still use it
                    process.stdout.write(JSON.stringify({
                        n_token: result,
                        error: "key_not_captured",
                        heap8_available: !!sandbox.__HEAP8__,
                    }));
                    process.exit(0);
                }
            }, 200);
        } else {
            process.stdout.write(JSON.stringify({ error: "hsj() returned null" }));
            process.exit(1);
        }
    } catch (e) {
        process.stderr.write(`[hsj_runner] hsj() error: ${e.message}\n`);
        const heapKey = extractKeyFromHeap();
        if (heapKey) {
            process.stdout.write(JSON.stringify({ key_hex: heapKey, source: "heap8_error" }));
            process.exit(0);
        }
        if (capturedKeyHex) {
            process.stdout.write(JSON.stringify({ key_hex: capturedKeyHex, source: "crypto_subtle_error" }));
            process.exit(0);
        }
        process.stdout.write(JSON.stringify({ error: `hsj() failed: ${e.message}` }));
        process.exit(1);
    }
})();
