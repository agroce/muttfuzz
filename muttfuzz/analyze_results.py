import csv
import sys

import scipy
import scipy.stats

files = sys.argv[1:]

roots = {}

for f in files:
    root = f.split(".")[0]
    if root not in roots:
        roots[root] = []
    with open(f) as fr:
        rows = csv.reader(fr)
        for row in rows:
            roots[root].append(row)

for r in roots:
    d_t = list(map(lambda x:x[1], roots[r]))
    d_m = list(map(lambda x:x[2], roots[r]))
    score = len(list(filter(lambda x: x != 0, d_m))) / len(list(d_m))
    print(r, "MEAN:", round(scipy.mean(d_t), 2), "MEDIAN:", round(scipy.median(d_t), 2), "RANGE: [" + round(min(d_t), 2), "-", round(max(d_t), 2), "]")
    print(r, "MUTATION SCORE:", round(score, 2))
    print()

for r1 in roots:
    d_t_1 = list(map(lambda x:x[1], roots[r1]))
    for r2 in roots:
        if r1 < r2:
            d_t_2 = list(map(lambda x:x[1], roots[r2]))
            try:
                print("Mann-Whitney U:", scipy.stats.mannwhitneyu(d_t_1, d_t_2))
            except:
                pass
