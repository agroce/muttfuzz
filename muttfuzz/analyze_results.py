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

for r, data in roots.items():
    d_t = list(map(lambda x:x[1], data))
    d_m = list(map(lambda x:x[2], data))
    score = len(list(filter(lambda x: x != 0, d_m))) / len(list(d_m))
    print(r, "MEAN:", round(scipy.mean(d_t), 2), "MEDIAN:", round(scipy.median(d_t), 2), "RANGE: [" + round(min(d_t), 2), "-", round(max(d_t), 2), "]")
    print(r, "MUTATION SCORE:", round(score, 2))
    print()

for r1, data1 in roots.items():
    d_t_1 = list(map(lambda x:x[1], data1))
    for r2, data2 in roots:
        if r1 < r2:
            d_t_2 = list(map(lambda x:x[1], data2))
            try:
                print("Mann-Whitney U:", scipy.stats.mannwhitneyu(d_t_1, d_t_2))
            except ValueError:
                pass
