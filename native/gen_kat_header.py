#!/usr/bin/env python3
"""
Generate native/selftest_kat.h from authoritative test-vector sources.

The generated header is committed so the Docker build needs no network access.
Re-run this only when refreshing vectors:

  python3 native/gen_kat_header.py \
      --acvp-keygen      ML-KEM-keyGen-FIPS203/internalProjection.json \
      --acvp-encapdecap  ML-KEM-encapDecap-FIPS203/internalProjection.json \
      --wycheproof       chacha20_poly1305_test.json \
      --rfc5869          rfc5869.txt \
      --rfc8439          rfc8439.txt \
      -o native/selftest_kat.h

Sources:
  ACVP        https://github.com/usnistgov/ACVP-Server/tree/master/gen-val/json-files
  Wycheproof  https://github.com/C2SP/wycheproof/tree/main/testvectors_v1
  RFC 5869    https://www.rfc-editor.org/rfc/rfc5869.txt  (HKDF-SHA256, A.1-A.3)
  RFC 8439    https://www.rfc-editor.org/rfc/rfc8439.txt  (ChaCha20, section 2.4.2)
"""
import argparse
import json
import re
import sys


def c_array(name, hexstr, const_type="uint8_t"):
    data = bytes.fromhex(hexstr) if hexstr else b""
    if not data:
        return f"static const {const_type} {name}[1] = {{0}}; /* empty */\n#define {name}_LEN 0\n"
    toks = [f"0x{b:02x}" for b in data]
    lines = []
    for i in range(0, len(toks), 16):
        lines.append("    " + ",".join(toks[i:i + 16]) + ("," if i + 16 < len(toks) else ""))
    return (f"static const {const_type} {name}[{len(data)}] = {{\n" + "\n".join(lines)
            + f"\n}};\n#define {name}_LEN {len(data)}\n")


def pick_mlkem768(groups, **want):
    for g in groups:
        if g.get("parameterSet") != "ML-KEM-768":
            continue
        if all(g.get(k) == v for k, v in want.items()):
            return g
    raise SystemExit(f"no ML-KEM-768 group with {want}")


def parse_rfc5869(text):
    """Return list of dicts for SHA-256 test cases A.1-A.3."""
    cases = []
    cur = None
    field = None
    for line in text.splitlines():
        m = re.match(r"^A\.(\d)\.\s+Test Case (\d)", line)
        if m:
            if cur:
                cases.append(cur)
            cur = {"name": f"RFC5869 A.{m.group(1)}"}
            field = None
            continue
        if cur is None:
            continue
        m = re.match(r"^\s+(IKM|salt|info|L|PRK|OKM)\s+=\s+(.*)$", line)
        if m:
            field = m.group(1)
            val = m.group(2).strip()
            cur[field] = val
            continue
        m = re.match(r"^\s+(0x[0-9a-f]+|[0-9a-f]{8,})\s*(\(.*\))?\s*$", line)
        if m and field in ("IKM", "salt", "info", "PRK", "OKM"):
            cur[field] += m.group(1)
            continue
        if line.strip().startswith("Hash =") and "SHA-1" in line:
            cur["sha1"] = True
    if cur:
        cases.append(cur)

    out = []
    for c in cases:
        if c.get("sha1") or "OKM" not in c:
            continue
        def hx(v):
            v = re.sub(r"\(.*?\)", "", v).replace("0x", "").replace(" ", "")
            if v in ("", "(0 octets)"):
                return ""
            return v
        out.append({
            "name": c["name"],
            "ikm": hx(c["IKM"]),
            "salt": hx(c.get("salt", "")),
            "info": hx(c.get("info", "")),
            "okm": hx(c["OKM"]),
        })
    if len(out) != 3:
        raise SystemExit(f"expected 3 SHA-256 HKDF cases, parsed {len(out)}")
    return out


def parse_rfc8439_242(text):
    # Anchor on the body headings (column 0), not the table-of-contents entries.
    start = re.search(r"^2\.4\.2\.  Example and Test Vector for the ChaCha20 Cipher\s*$", text, re.M)
    end = re.search(r"^2\.5\.  The Poly1305 Algorithm\s*$", text, re.M)
    if not start or not end:
        raise SystemExit("RFC 8439 section 2.4.2 not found")
    sec = text[start.end():end.start()]

    def block(title):
        part = sec.split(title, 1)[1]
        out = []
        for line in part.splitlines()[1:]:
            m = re.match(r"^\s+(\d{3})\s+((?:[0-9a-f]{2} ?)+)", line)
            if not m:
                if out:
                    break
                continue
            out.append(m.group(2).replace(" ", ""))
        return "".join(out)

    pt = block("Plaintext Sunscreen:")
    ct = block("Ciphertext Sunscreen:")
    key = "".join(f"{i:02x}" for i in range(32))
    nonce = "000000000000004a00000000"
    assert bytes.fromhex(pt).startswith(b"Ladies and Gentlemen"), pt
    assert len(pt) == len(ct), (len(pt), len(ct))
    return {"key": key, "nonce": nonce, "pt": pt, "ct": ct}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--acvp-keygen", required=True)
    ap.add_argument("--acvp-encapdecap", required=True)
    ap.add_argument("--wycheproof", required=True)
    ap.add_argument("--rfc5869", required=True)
    ap.add_argument("--rfc8439", required=True)
    ap.add_argument("-o", "--output", required=True)
    args = ap.parse_args()

    kg = json.load(open(args.acvp_keygen))
    ed = json.load(open(args.acvp_encapdecap))
    wy = json.load(open(args.wycheproof))
    rfc5869 = parse_rfc5869(open(args.rfc5869, encoding="utf-8", errors="replace").read())
    rfc8439 = parse_rfc8439_242(open(args.rfc8439, encoding="utf-8", errors="replace").read())

    out = []
    out.append("/* AUTO-GENERATED by native/gen_kat_header.py - do not edit. */\n")
    out.append("#ifndef E2EE_SELFTEST_KAT_H\n#define E2EE_SELFTEST_KAT_H\n#include <stdint.h>\n#include <stddef.h>\n\n")
    out.append(f"#define KAT_ACVP_KEYGEN_VSID {kg.get('vsId', 0)}\n")
    out.append(f"#define KAT_ACVP_ENCAPDECAP_VSID {ed.get('vsId', 0)}\n\n")

    # --- ML-KEM keyGen ---------------------------------------------------
    g = pick_mlkem768(kg["testGroups"])
    t = g["tests"][0]
    out.append(f"/* ACVP ML-KEM-768 keyGen tgId={g['tgId']} tcId={t['tcId']} */\n")
    out.append(c_array("KAT_KEYGEN_D", t["d"]))
    out.append(c_array("KAT_KEYGEN_Z", t["z"]))
    out.append(c_array("KAT_KEYGEN_EK", t["ek"]))
    out.append(c_array("KAT_KEYGEN_DK", t["dk"]))
    out.append("\n")

    # --- ML-KEM encapsulation -------------------------------------------
    g = pick_mlkem768(ed["testGroups"], function="encapsulation")
    t = g["tests"][0]
    out.append(f"/* ACVP ML-KEM-768 encapsulation tgId={g['tgId']} tcId={t['tcId']} */\n")
    out.append(c_array("KAT_ENCAP_EK", t["ek"]))
    out.append(c_array("KAT_ENCAP_DK", t["dk"]))
    out.append(c_array("KAT_ENCAP_M", t["m"]))
    out.append(c_array("KAT_ENCAP_C", t["c"]))
    out.append(c_array("KAT_ENCAP_K", t["k"]))
    out.append("\n")

    # --- ML-KEM decapsulation (valid + implicit rejection) --------------
    g = pick_mlkem768(ed["testGroups"], function="decapsulation")
    by_reason = {}
    for t in g["tests"]:
        by_reason.setdefault(t.get("reason"), t)
    valid = by_reason.get("valid decapsulation")
    reject = by_reason.get("modified ciphertext")
    if not valid or not reject:
        raise SystemExit(f"decap reasons available: {list(by_reason)}")
    out.append(f"/* ACVP ML-KEM-768 decapsulation tgId={g['tgId']} tcId={valid['tcId']} (valid) */\n")
    out.append(c_array("KAT_DECAP_VALID_DK", valid["dk"]))
    out.append(c_array("KAT_DECAP_VALID_C", valid["c"]))
    out.append(c_array("KAT_DECAP_VALID_K", valid["k"]))
    out.append(f"/* ACVP ML-KEM-768 decapsulation tgId={g['tgId']} tcId={reject['tcId']} (modified ciphertext -> implicit rejection) */\n")
    out.append(c_array("KAT_DECAP_REJECT_DK", reject["dk"]))
    out.append(c_array("KAT_DECAP_REJECT_C", reject["c"]))
    out.append(c_array("KAT_DECAP_REJECT_K", reject["k"]))
    out.append("\n")

    # --- HKDF-SHA256 (RFC 5869) ------------------------------------------
    out.append("typedef struct {\n    const char *name;\n"
               "    const uint8_t *ikm; size_t ikm_len;\n"
               "    const uint8_t *salt; size_t salt_len;\n"
               "    const uint8_t *info; size_t info_len;\n"
               "    const uint8_t *okm; size_t okm_len;\n} hkdf_case_t;\n\n")
    names = []
    for i, c in enumerate(rfc5869):
        p = f"KAT_HKDF{i}"
        out.append(f"/* {c['name']} */\n")
        for f in ("ikm", "salt", "info", "okm"):
            out.append(c_array(f"{p}_{f.upper()}", c[f]))
        names.append((c["name"], p))
    out.append("static const hkdf_case_t HKDF_CASES[] = {\n")
    for name, p in names:
        out.append(f"    {{\"{name}\", {p}_IKM, {p}_IKM_LEN, {p}_SALT, {p}_SALT_LEN, "
                   f"{p}_INFO, {p}_INFO_LEN, {p}_OKM, {p}_OKM_LEN}},\n")
    out.append("};\n#define HKDF_CASES_N (sizeof(HKDF_CASES)/sizeof(HKDF_CASES[0]))\n\n")

    # --- ChaCha20 stream (RFC 8439 2.4.2) --------------------------------
    out.append("/* RFC 8439 section 2.4.2: ChaCha20 keystream check (counter=1, as used by the AEAD data path) */\n")
    out.append(c_array("KAT_RFC8439_KEY", rfc8439["key"]))
    out.append(c_array("KAT_RFC8439_NONCE", rfc8439["nonce"]))
    out.append(c_array("KAT_RFC8439_PT", rfc8439["pt"]))
    out.append(c_array("KAT_RFC8439_CT", rfc8439["ct"]))
    out.append("\n")

    # --- AEAD, empty AAD (Wycheproof) ------------------------------------
    sel = []
    for g in wy["testGroups"]:
        if g.get("ivSize") != 96 or g.get("keySize") != 256 or g.get("tagSize") != 128:
            continue
        for t in g["tests"]:
            if t["aad"] == "" and t["result"] == "valid":
                sel.append(t)
    if len(sel) < 4:
        raise SystemExit("too few empty-AAD wycheproof cases")
    # keep a spread of message sizes: empty, small, block-ish, large
    sel.sort(key=lambda t: len(t["msg"]))
    chosen = [sel[0], sel[1], sel[len(sel) // 3], sel[2 * len(sel) // 3], sel[-1]]
    out.append("typedef struct {\n    int tcId;\n    const uint8_t *key; const uint8_t *iv;\n"
               "    const uint8_t *msg; size_t msg_len;\n"
               "    const uint8_t *ct; const uint8_t *tag;\n} aead_case_t;\n\n")
    wy_names = []
    for t in chosen:
        p = f"KAT_WY{t['tcId']}"
        out.append(f"/* Wycheproof chacha20_poly1305 tcId={t['tcId']} ({t.get('comment','')!s}) */\n")
        out.append(c_array(f"{p}_KEY", t["key"]))
        out.append(c_array(f"{p}_IV", t["iv"]))
        out.append(c_array(f"{p}_MSG", t["msg"]))
        out.append(c_array(f"{p}_CT", t["ct"]))
        out.append(c_array(f"{p}_TAG", t["tag"]))
        wy_names.append((t["tcId"], p))
    out.append("static const aead_case_t AEAD_CASES[] = {\n")
    for tc, p in wy_names:
        out.append(f"    {{{tc}, {p}_KEY, {p}_IV, {p}_MSG, {p}_MSG_LEN, {p}_CT, {p}_TAG}},\n")
    out.append("};\n#define AEAD_CASES_N (sizeof(AEAD_CASES)/sizeof(AEAD_CASES[0]))\n\n")

    out.append("#endif /* E2EE_SELFTEST_KAT_H */\n")
    with open(args.output, "w") as f:
        f.write("".join(out))
    print(f"wrote {args.output}: hkdf={len(rfc5869)} aead={len(chosen)} rfc8439_pt={len(rfc8439['pt'])//2}B",
          file=sys.stderr)


if __name__ == "__main__":
    main()
