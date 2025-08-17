import yara, argparse, pathlib

if __name__=="__main__":
    ap=argparse.ArgumentParser()
    ap.add_argument("rules")
    ap.add_argument("target")
    args=ap.parse_args()

    rules=yara.compile(filepath=args.rules)
    target=pathlib.Path(args.target)
    if target.is_file():
        m=rules.match(str(target))
        print(m)
    else:
        for f in target.rglob("*"):
            try:
                m=rules.match(str(f))
                if m: print(f"{f}: {m}")
            except: pass
