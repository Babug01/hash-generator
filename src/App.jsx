import { useRef, useState } from "react";
import Header from "./components/Header";

const REPO_URL = "https://github.com/Babug01/hash-generator";

// Pure-JS MD5 (RFC 1321) — Web Crypto deliberately doesn't implement MD5
// (it's broken for anything security-sensitive), but MD5 is still what a lot
// of legacy checksums/artifacts ship with, so it's vendored here rather than
// pulled from a third-party package. Verified byte-for-byte against Node's
// `crypto.createHash("md5")` across the empty string, "hello", the classic
// pangram, and inputs straddling the 55/56-byte padding-block boundary
// before being written in here.
function md5Hex(bytes) {
  function rotl(x, c) {
    return (x << c) | (x >>> (32 - c));
  }
  function add32(a, b) {
    return (a + b) >>> 0;
  }

  const SHIFTS = [
    7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
    5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20,
    4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
    6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
  ];
  const K = new Int32Array(64);
  for (let i = 0; i < 64; i++) K[i] = Math.floor(Math.abs(Math.sin(i + 1)) * 4294967296);

  let a0 = 0x67452301, b0 = 0xefcdab89, c0 = 0x98badcfe, d0 = 0x10325476;

  const origLenBits = BigInt(bytes.length) * 8n;
  let padLen = bytes.length + 1;
  while (padLen % 64 !== 56) padLen++;
  const padded = new Uint8Array(padLen + 8);
  padded.set(bytes);
  padded[bytes.length] = 0x80;
  const dv = new DataView(padded.buffer);
  dv.setBigUint64(padded.length - 8, origLenBits, true);

  for (let chunkStart = 0; chunkStart < padded.length; chunkStart += 64) {
    const M = new Uint32Array(16);
    for (let j = 0; j < 16; j++) M[j] = dv.getUint32(chunkStart + j * 4, true);
    let A = a0, B = b0, C = c0, D = d0;
    for (let i = 0; i < 64; i++) {
      let F, g;
      if (i < 16) { F = (B & C) | (~B & D); g = i; }
      else if (i < 32) { F = (D & B) | (~D & C); g = (5 * i + 1) % 16; }
      else if (i < 48) { F = B ^ C ^ D; g = (3 * i + 5) % 16; }
      else { F = C ^ (B | ~D); g = (7 * i) % 16; }
      F = add32(add32(add32(F, A), K[i]), M[g]);
      A = D; D = C; C = B;
      B = add32(B, rotl(F, SHIFTS[i]));
    }
    a0 = add32(a0, A); b0 = add32(b0, B); c0 = add32(c0, C); d0 = add32(d0, D);
  }

  const out = new Uint8Array(16);
  const outDv = new DataView(out.buffer);
  outDv.setUint32(0, a0 >>> 0, true);
  outDv.setUint32(4, b0 >>> 0, true);
  outDv.setUint32(8, c0 >>> 0, true);
  outDv.setUint32(12, d0 >>> 0, true);
  return Array.from(out).map((b) => b.toString(16).padStart(2, "0")).join("");
}

function bufToHex(buf) {
  return Array.from(new Uint8Array(buf)).map((b) => b.toString(16).padStart(2, "0")).join("");
}

const DIGEST_ALGOS = [
  { id: "MD5", label: "MD5 (legacy)" },
  { id: "SHA-1", label: "SHA-1" },
  { id: "SHA-256", label: "SHA-256" },
  { id: "SHA-384", label: "SHA-384" },
  { id: "SHA-512", label: "SHA-512" },
];

async function computeAllHashes(bytes) {
  const results = {};
  for (const { id } of DIGEST_ALGOS) {
    if (id === "MD5") {
      results[id] = md5Hex(bytes);
    } else {
      const digest = await crypto.subtle.digest(id, bytes);
      results[id] = bufToHex(digest);
    }
  }
  return results;
}

async function computeHmac(secret, message, algo) {
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: algo },
    false,
    ["sign"]
  );
  const sig = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(message));
  return bufToHex(sig);
}

const styles = {
  root: { minHeight: "100dvh", display: "flex", flexDirection: "column" },
  content: { fontFamily: "system-ui, sans-serif", padding: "24px 32px", maxWidth: 900, margin: "0 auto", color: "var(--text, #1a1a1a)", width: "100%", boxSizing: "border-box", background: "var(--bg-subtle, #f0efed)", flex: 1 },
  title: { fontSize: 22, fontWeight: 700, margin: 0 },
  subtitle: { fontSize: 13, opacity: 0.6, margin: "4px 0 20px" },
  tabs: { display: "flex", gap: 8, marginBottom: 20 },
  tabBtn: (active) => ({
    padding: "8px 16px", borderRadius: 8, border: active ? "none" : "1px solid var(--border, #e5e7eb)",
    background: active ? "var(--accent, #4f46e5)" : "transparent", color: active ? "#fff" : "var(--text, #1a1a1a)",
    cursor: "pointer", fontSize: 13, fontWeight: 600,
  }),
  textarea: {
    width: "100%", minHeight: 140, padding: 12, borderRadius: 8, border: "1px solid var(--border, #e5e7eb)",
    background: "var(--input-bg, #f9fafb)", color: "var(--text, #1a1a1a)", fontSize: 13, boxSizing: "border-box",
    fontFamily: "'SFMono-Regular', Consolas, monospace", resize: "vertical",
  },
  input: {
    padding: "9px 12px", borderRadius: 6, border: "1px solid var(--border, #e5e7eb)",
    background: "var(--input-bg, #f9fafb)", color: "var(--text, #1a1a1a)", fontSize: 13,
    fontFamily: "'SFMono-Regular', Consolas, monospace", width: "100%", boxSizing: "border-box",
  },
  select: {
    padding: "8px 10px", borderRadius: 6, border: "1px solid var(--border, #e5e7eb)", background: "var(--input-bg, #f9fafb)",
    color: "var(--text, #1a1a1a)", fontSize: 13,
  },
  row: { display: "flex", gap: 10, marginTop: 12, marginBottom: 16, alignItems: "center", flexWrap: "wrap" },
  btn: (kind) => ({
    padding: "9px 18px", borderRadius: 6, border: kind === "primary" ? "none" : "1px solid var(--border, #e5e7eb)",
    background: kind === "primary" ? "var(--accent, #4f46e5)" : "transparent",
    color: kind === "primary" ? "#fff" : "var(--text, #1a1a1a)", cursor: "pointer", fontSize: 13, fontWeight: 600,
  }),
  fileNote: { fontSize: 12, opacity: 0.65 },
  note: {
    fontSize: 12, padding: "10px 14px", borderRadius: 8, border: "1px solid var(--border, #e5e7eb)",
    background: "rgba(224,160,92,0.08)", color: "#c97f2e", marginBottom: 16,
  },
  resultRow: {
    display: "flex", alignItems: "center", gap: 10, padding: "10px 12px", borderRadius: 8,
    border: "1px solid var(--border, #e5e7eb)", background: "var(--input-bg, #f9fafb)", marginBottom: 8,
  },
  resultLabel: { fontSize: 12, fontWeight: 700, width: 110, flexShrink: 0 },
  resultValue: { fontSize: 12, fontFamily: "'SFMono-Regular', Consolas, monospace", wordBreak: "break-all", flex: 1, color: "var(--text, #1a1a1a)" },
  iconBtn: {
    padding: "4px 10px", borderRadius: 6, border: "1px solid var(--border, #e5e7eb)", background: "transparent",
    color: "var(--text, #1a1a1a)", cursor: "pointer", fontSize: 11, flexShrink: 0,
  },
  fieldLabel: { fontSize: 12, fontWeight: 600, marginBottom: 6, opacity: 0.75 },
  field: { marginBottom: 14 },
};

function CopyButton({ text }) {
  const [copied, setCopied] = useState(false);
  return (
    <button
      style={styles.iconBtn}
      onClick={() => {
        navigator.clipboard.writeText(text);
        setCopied(true);
        setTimeout(() => setCopied(false), 1500);
      }}
    >
      {copied ? "Copied" : "Copy"}
    </button>
  );
}

function HashTab() {
  const [text, setText] = useState("");
  const [file, setFile] = useState(null);
  const [results, setResults] = useState(null);
  const [error, setError] = useState(null);
  const [busy, setBusy] = useState(false);
  const fileInputRef = useRef(null);

  async function compute() {
    setError(null);
    setBusy(true);
    try {
      let bytes;
      if (file) {
        bytes = new Uint8Array(await file.arrayBuffer());
      } else {
        bytes = new TextEncoder().encode(text);
      }
      setResults(await computeAllHashes(bytes));
    } catch (e) {
      setError(e.message);
      setResults(null);
    } finally {
      setBusy(false);
    }
  }

  function handleFileChosen(e) {
    const f = e.target.files?.[0];
    if (!f) return;
    setFile(f);
    setResults(null);
  }

  function clearFile() {
    setFile(null);
    if (fileInputRef.current) fileInputRef.current.value = "";
  }

  function clearAll() {
    setText("");
    clearFile();
    setResults(null);
    setError(null);
  }

  return (
    <div>
      {!file ? (
        <textarea style={styles.textarea} value={text} onChange={(e) => { setText(e.target.value); setResults(null); }} placeholder="Type or paste text to hash..." spellCheck={false} />
      ) : (
        <div style={{ ...styles.textarea, display: "flex", alignItems: "center", justifyContent: "center", minHeight: 60 }}>
          <span style={styles.fileNote}>{file.name} ({file.size.toLocaleString()} bytes) — text input disabled while a file is selected</span>
        </div>
      )}

      <div style={styles.row}>
        <button style={styles.btn("primary")} onClick={compute} disabled={busy}>{busy ? "Computing..." : "Compute Hashes"}</button>
        <button style={styles.btn("secondary")} onClick={() => fileInputRef.current?.click()}>Upload File</button>
        {file && <button style={styles.btn("secondary")} onClick={clearFile}>Use Text Instead</button>}
        <button style={styles.btn("secondary")} onClick={clearAll}>Clear</button>
        <input ref={fileInputRef} type="file" style={{ display: "none" }} onChange={handleFileChosen} />
      </div>

      <div style={styles.note}>
        MD5 is shown for legacy checksum comparison only (e.g. matching a vendor-published MD5 sum) —
        it's cryptographically broken and must never be relied on for anything security-sensitive.
      </div>

      {error && <div style={{ ...styles.note, borderColor: "#e05c5c", background: "rgba(224,92,92,0.08)", color: "#e05c5c" }}>{error}</div>}

      {results && DIGEST_ALGOS.map(({ id, label }) => (
        <div key={id} style={styles.resultRow}>
          <span style={styles.resultLabel}>{label}</span>
          <span style={styles.resultValue}>{results[id]}</span>
          <CopyButton text={results[id]} />
        </div>
      ))}
    </div>
  );
}

function HmacTab() {
  const [secret, setSecret] = useState("");
  const [message, setMessage] = useState("");
  const [algo, setAlgo] = useState("SHA-256");
  const [result, setResult] = useState(null);
  const [error, setError] = useState(null);
  const [busy, setBusy] = useState(false);

  async function compute() {
    setError(null);
    setBusy(true);
    try {
      setResult(await computeHmac(secret, message, algo));
    } catch (e) {
      setError(e.message);
      setResult(null);
    } finally {
      setBusy(false);
    }
  }

  return (
    <div>
      <div style={styles.field}>
        <div style={styles.fieldLabel}>Secret key</div>
        <input style={styles.input} type="text" value={secret} onChange={(e) => setSecret(e.target.value)} placeholder="Shared secret" />
      </div>
      <div style={styles.field}>
        <div style={styles.fieldLabel}>Message</div>
        <textarea style={styles.textarea} value={message} onChange={(e) => setMessage(e.target.value)} placeholder="Message to authenticate..." spellCheck={false} />
      </div>
      <div style={styles.row}>
        <select style={styles.select} value={algo} onChange={(e) => setAlgo(e.target.value)}>
          <option value="SHA-256">HMAC-SHA-256</option>
          <option value="SHA-512">HMAC-SHA-512</option>
        </select>
        <button style={styles.btn("primary")} onClick={compute} disabled={busy}>{busy ? "Computing..." : "Compute HMAC"}</button>
      </div>

      {error && <div style={{ ...styles.note, borderColor: "#e05c5c", background: "rgba(224,92,92,0.08)", color: "#e05c5c" }}>{error}</div>}

      {result && (
        <div style={styles.resultRow}>
          <span style={styles.resultLabel}>HMAC-{algo}</span>
          <span style={styles.resultValue}>{result}</span>
          <CopyButton text={result} />
        </div>
      )}
    </div>
  );
}

export default function App() {
  const [tab, setTab] = useState("hash");

  return (
    <div style={styles.root}>
      <Header repoUrl={REPO_URL} />
      <div style={styles.content}>
        <h1 style={styles.title}>Hash Generator</h1>
        <p style={styles.subtitle}>
          Compute MD5, SHA-1, SHA-256, SHA-384, SHA-512, and HMAC digests of text or an uploaded file,
          entirely in the browser via the Web Crypto API — nothing you type or upload ever leaves your machine.
        </p>

        <div style={styles.tabs}>
          <button style={styles.tabBtn(tab === "hash")} onClick={() => setTab("hash")}>Hash</button>
          <button style={styles.tabBtn(tab === "hmac")} onClick={() => setTab("hmac")}>HMAC</button>
        </div>

        {tab === "hash" ? <HashTab /> : <HmacTab />}
      </div>
    </div>
  );
}
