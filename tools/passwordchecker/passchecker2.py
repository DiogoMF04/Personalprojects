import sys, math, re, getpass
COMMON = {"password","123456","qwerty","letmein","admin","welcome"}
CHARSETS = [
    (re.compile(r"[a-z]"), 26),
    (re.compile(r"[A-Z]"), 26),
    (re.compile(r"[0-9]"), 10),
    (re.compile(r"[^a-zA-Z0-9]"), 33),
]

def charset_space(pw:str)->int:
    return max(sum(size for rgx,size in CHARSETS if rgx.search(pw)), 1)

def entropy_bits(pw:str)->float:
    return len(pw) * math.log2(charset_space(pw))

def penalties(pw:str)->int:
    p=0
    if pw.lower() in COMMON: p+=30
    if re.search(r"(.)\1{2,}", pw): p+=10
    if re.search(r"(1234|abcd|qwer|pass|admin)", pw.lower()): p+=15
    if len(set(pw)) <= max(3, len(pw)//3): p+=10
    return p

def score(pw:str)->int:
    s = min(100, int(entropy_bits(pw))) - penalties(pw)
    return max(0, min(100, s))

if __name__ == "__main__":
    pw = sys.stdin.read().strip() if not sys.stdin.isatty() else getpass.getpass("Password: ")
    s = score(pw)
    verdict = "Weak" if s<40 else ("Moderate" if s<70 else "Strong")
    print(f"Score: {s}/100 — {verdict}")
