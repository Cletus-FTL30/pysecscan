import math
from collections import Counter


def shannon(s):
    # bits per character. english text sits around 4, random base64 around
    # 5.5-6, a pure hex hash maxes out near 4 (only 16 possible chars).
    # we use this to pick out "random-looking" strings that named rules miss.
    if not s:
        return 0.0
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in Counter(s).values())
