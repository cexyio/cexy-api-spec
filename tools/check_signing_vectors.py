"""Independent check of conformance/signing/vectors.json: recomputes every canonical line and
signature from the documented scheme (written without the server code), plus the WS and negative
cases. Usage: python tools/check_signing_vectors.py [conformance/signing/vectors.json]"""
import hashlib, hmac, json, sys, urllib.parse
UNRES = set(b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~")
def enc(b: bytes) -> str:
    return "".join(chr(c) if c in UNRES else "%%%02X" % c for c in b)
def canon_path(p: str) -> str:
    return "/".join(enc(urllib.parse.unquote_to_bytes(seg)) for seg in p.split("/"))
def canon_query(q: str) -> str:
    if not q: return ""
    pairs=[]
    for part in q.split("&"):
        n,_,v = part.partition("=")
        pairs.append((enc(urllib.parse.unquote_to_bytes(n)), enc(urllib.parse.unquote_to_bytes(v)), "=" in part))
    pairs.sort(key=lambda t:(t[0].encode(),t[1].encode()))
    return "&".join(f"{n}={v}" for n,v,_ in pairs)
d=json.load(open(sys.argv[1] if len(sys.argv) > 1 else "conformance/signing/vectors.json")); ok=True
for c in d["rest"]:
    path,_,q = c["request_target"].partition("?")
    cp, cq = canon_path(path), canon_query(q)
    body = c["body"].encode()
    bh = hashlib.sha256(body).hexdigest()
    creq = "\n".join([d["scheme"], c["method"], cp, cq, d["timestamp"], d["nonce"], bh])
    sig = hmac.new(d["secret"].encode(), creq.encode(), hashlib.sha256).hexdigest()
    res = [cp==c["canonical_path"], cq==c["canonical_query"], bh==c["body_sha256"], creq==c["canonical_request"], sig==c["headers"]["X-API-Signature"]]
    ok &= all(res)
    print(f"{c['name']:40} {'OK' if all(res) else 'DIFF '+str(res)+' '+repr((cp,c['canonical_path'],cq,c['canonical_query']))}")
w = d["ws"]
msg = "CEXY-WS-AUTH-v1\n" + w["welcome"]["connection_id"] + "\n" + w["welcome"]["challenge"]
ws_ok = msg == w["message"] and hmac.new(d["secret"].encode(), msg.encode(), hashlib.sha256).hexdigest() == w["auth_key"]["signature"]
print(f"{'ws_auth_key':40} {'OK' if ws_ok else 'DIFF'}")
n = d["negative"]
right = hmac.new(d["secret"].encode(), n["canonical_request"].encode(), hashlib.sha256).hexdigest()
wrong = hmac.new(n["wrong_secret"].encode(), n["canonical_request"].encode(), hashlib.sha256).hexdigest()
neg_ok = right == n["signature_with_right_secret"] and wrong == n["signature_with_wrong_secret"] and right != wrong
print(f"{'negative_wrong_secret':40} {'OK' if neg_ok else 'DIFF'}")
sys.exit(0 if ok and ws_ok and neg_ok else 1)
