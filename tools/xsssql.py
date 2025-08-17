import argparse, urllib.parse, urllib.request, re, ssl
ssl._create_default_https_context = ssl._create_unverified_context

XSS_PAYLOAD = "\"'><script>alert(1)</script>"
SQL_ERRORS = [r"SQL syntax", r"mysql_fetch", r"ORA-\\d+", r"SQLite/JDBC", r"pg_query"]

def fuzz(url:str):
    parsed=urllib.parse.urlsplit(url)
    qs=urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
    if not qs:
        print("No query parameters to fuzz."); return
    for k in qs:
        fuzzed=dict(qs); fuzzed[k]=[XSS_PAYLOAD]
        q=urllib.parse.urlencode({kk:vv[0] for kk,vv in fuzzed.items()})
        target=urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, parsed.path, q, parsed.fragment))
        try:
            with urllib.request.urlopen(target, timeout=6) as r:
                body=r.read().decode(errors='ignore')
                if XSS_PAYLOAD in body:
                    print(f"[XSS?] Parameter '{k}' reflected at {target}")
                if any(re.search(p, body, re.I) for p in SQL_ERRORS):
                    print(f"[SQLi error?] DB error patterns seen for '{k}' at {target}")
        except Exception as e:
            print(f"[!] Error fetching {target}: {e}")

if __name__=="__main__":
    ap=argparse.ArgumentParser(description="Lightweight fuzzer for lab apps.")
    ap.add_argument("url", help="URL with query params (e.g., http://lab/search?q=test)")
    args=ap.parse_args()
    fuzz(args.url)
