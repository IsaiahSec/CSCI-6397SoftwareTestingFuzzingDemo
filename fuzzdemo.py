#!/usr/bin/env python3
"""
fuzzdemo.py - the same buggy program, attacked three ways.

    python fuzzdemo.py black
    python fuzzdemo.py grey
    python fuzzdemo.py white
"""
import argparse, random, string, sys, time
from collections import Counter

# ======================= THE PROGRAM UNDER TEST =======================
MAX_NAME = 10

def make_label(data, check):
    """data = a style letter + a name.  Style 'e' means HTML-escape the name."""
    name = data[1:]
    if not 1 <= len(name) <= MAX_NAME:            # input check: EP and BVA test this boundary
        return
    buf = [""] * (3 * MAX_NAME)                   # room for 3 characters per name character
    pos = 0
    for i in range(1, len(data)):
        if check(0, "e") and check(i, "<"):       # style is 'e'  AND  this character is '<'
            for c in "&lt;":                      # '<' becomes 4 characters...
                buf[pos] = c                      # BUG: ...but we only made room for 3
                pos += 1
        else:
            buf[pos] = data[i]
            pos += 1

# check(i, x) just asks "is data[i] == x?" and reports the answer to the fuzzer
# (a real fuzzer gets this by instrumenting the program automatically).

# ======================= THE THREE FUZZERS =======================
SEED = "pHello, you"                              # style 'p' (plain) + a valid name

def mutate(text):                                 # shared by black and grey: random edits
    s = list(text)
    for _ in range(random.choice((1, 2, 4))):
        i = random.randrange(len(s))
        if random.random() < 0.7:
            s[i] = random.choice(string.printable[:94])          # change one character
        else:
            n = random.randint(1, 6)                              # copy a chunk of text elsewhere
            a, b = random.randrange(len(s) - n + 1), random.randrange(len(s) - n + 1)
            s[b:b + n] = s[a:a + n]
    return "".join(s)

def black_box(run, say, paths):
    # SEES: nothing but "did it crash?".   Mutates the same seed every time; learns nothing.
    while True:
        crashed, _ = run(mutate(SEED))
        if crashed:
            return

def grey_box(run, say, paths):
    # SEES: which branches ran, and how often.   Keeps any input that reaches something new.
    corpus = [SEED]
    paths.add(coverage(run(SEED)[1]))
    while True:
        data = mutate(random.choice(corpus))
        crashed, probes = run(data)
        if crashed:
            return
        if paths.add(coverage(probes)):           # something new ran -> keep it and build on it
            corpus.append(data)
            say(f"  new path -> keep  {data!r}")

def white_box(run, say, paths):
    # SEES: the conditions the code checks.   Builds the input that answers each one differently.
    seen, todo = {SEED}, [(SEED, None)]
    while todo:
        data, why = todo.pop()
        if why:
            i, want = why
            what = "the style" if i == 0 else f"character {i}"
            say(f"  code asked: is {what} {want!r}?  no  ->  try {want!r}")
        crashed, probes = run(data)
        if crashed:
            return
        paths.add(coverage(probes))
        for i, want, ok in probes:
            if not ok:
                child = data[:i] + want + data[i + 1:]
                if child not in seen:
                    seen.add(child)
                    todo.append((child, (i, want)))

# ======================= PLUMBING (counters, coverage) =======================
def coverage(probes):
    """Which branch outcomes happened, and how many times (bucketed like AFL does)."""
    counts = Counter(("style" if i == 0 else "char", ok) for i, _, ok in probes)
    bucket = lambda n: next(b for b, lim in enumerate((1, 2, 3, 7, 15, 31, 127, 999)) if n <= lim)
    return {(site, ok, bucket(n)) for (site, ok), n in counts.items()}

class Paths:
    def __init__(self): self.seen = set()
    def empty(self): return not self.seen
    def add(self, features):                      # True if any feature is new
        new = features - self.seen
        self.seen |= new
        return bool(new)

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("mode", choices=("black", "grey", "white"))
    ap.add_argument("--seconds", type=float, default=30)
    ap.add_argument("--seed", type=int, default=1)
    args = ap.parse_args()
    random.seed(args.seed)

    sees = {"black": "nothing but 'did it crash?'",
            "grey": "which branches ran (coverage); keeps inputs that reach something new",
            "white": "the code's own conditions; works out inputs that answer them differently"}
    print(f"\n  {args.mode.upper()}-BOX fuzzer sees: {sees[args.mode]}\n")

    paths, n, start, last = Paths(), {"tries": 0, "crashes": 0, "input": None}, time.time(), [0]

    def show(force=False):
        if force or time.time() - last[0] > 0.05:
            p = "-" if args.mode == "black" else len(paths.seen)
            sys.stdout.write(f"\r  tries {n['tries']:>9,}    paths {p:>3}    crashes {n['crashes']}")
            sys.stdout.flush(); last[0] = time.time()

    def say(text):                                # print a line above the live counters
        sys.stdout.write("\r" + " " * 60 + "\r" + text + "\n"); show(True)

    def run(data):
        if time.time() - start > args.seconds:
            raise TimeoutError
        probes = []
        def check(i, want):
            ok = data[i] == want
            probes.append((i, want, ok))
            return ok
        try:
            make_label(data, check); crashed = False
        except IndexError:                        # Python's stand-in for a buffer overflow being caught
            crashed = True
        n["tries"] += 1; n["crashes"] += crashed
        if crashed: n["input"] = data
        show(crashed)
        return crashed, probes

    fuzz = {"black": black_box, "grey": grey_box, "white": white_box}[args.mode]
    try:
        fuzz(run, say, paths)
    except TimeoutError:
        pass
    show(True)
    print("\n")
    if n["crashes"]:
        print(f"  CRASH after {time.time() - start:.1f}s with input {n['input']!r}")
        print("  style 'e' + a name full of '<' overflows the buffer")
    else:
        print(f"  no crash found in {args.seconds:.0f}s")

if __name__ == "__main__":
    main()
