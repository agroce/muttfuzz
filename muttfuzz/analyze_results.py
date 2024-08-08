import csv
import sys

import matplotlib
import matplotlib.pyplot as plt
from matplotlib.backends.backend_pdf import PdfPages

import scipy
import scipy.stats

def main():
    matplotlib.rcParams['pdf.fonttype'] = 42
    matplotlib.rcParams['ps.fonttype'] = 42

    files = sys.argv[1:]

    roots = {}

    all_mutants = {}
    ever_unkilled = {}

    max_unkilled = 0.0

    for f in files:
        root = f.split(".")[0]
        if root not in roots:
            roots[root] = []
        with open(f) as fr:
            rows = csv.reader(fr)
            for row in rows:
                roots[root].append(row)
                all_mutants[row[0]] = True
                if int(row[2]) == 0:
                    ever_unkilled[row[0]] = True
                    max_unkilled = max(max_unkilled, float(row[1]))

    print("THERE ARE", len(all_mutants.keys()), "MUTANTS")
    print()

    print("NOTE: ALL UNKILLED MUTANTS WILL BE ASSIGNED THE MAXIMUM TIME FOR AN UNKILLED MUTANT")
    print()

    cap_max = {}
    for r, data in roots.items():
        new_data = []
        for row in data:
            new_row = list(row)
            if int(row[2]) == 0:
                if (max_unkilled - float(row[1])) > (max_unkilled * 0.1):
                    print("WARNING: REPLACING DATA POINT FOR UNKILLED MUTANT WITH MORE THAN 10% DIFFERENCE")
                    print("ORIGINAL VALUE:", float(row[1]), "REPLACED WITH", max_unkilled)
                new_row[1] = max_unkilled
            new_data.append(new_row)
        cap_max[r] = new_data
    roots = cap_max

    graph = []
    label = []

    for r, data in roots.items():
        d_t = list(map(lambda x:float(x[1]), data))
        graph.append(d_t)
        label.append(r)
        d_m = list(map(lambda x:int(x[2]), data))
        print (r, "# DATA POINTS:", len(d_t))
        score = len(list(filter(lambda x: x != 0, d_m))) / len(list(d_m))
        print(r, "MEAN:", round(scipy.mean(d_t), 2), "MEDIAN:", round(scipy.median(d_t), 2),
              "RANGE: [" + str(round(min(d_t), 2)) + " - " + str(round(max(d_t), 2)) + "]")
        print(r, "MUTATION SCORE:", round(score, 2))
        print()

    for r1, data1 in roots.items():
        d_t_1 = list(map(lambda x:float(x[1]), data1))
        for r2, data2 in roots.items():
            if r1 < r2:
                d_t_2 = list(map(lambda x:float(x[1]), data2))
                try:
                    print("Mann-Whitney U:", scipy.stats.mannwhitneyu(d_t_1, d_t_2))
                except ValueError:
                    pass

    f1 = plt.figure()
    plt.ylabel("Time(s)")
    plt.boxplot(graph, labels=label)
    pp = PdfPages("all.pdf")
    pp.savefig(f1)
    pp.close()
    print("SAVED GRAPH OF ALL DATA TO all.pdf")

    print()
    print("STATISTICS OVER ONLY MUTANTS EVER UNKILLED")
    print("THERE ARE", len(ever_unkilled.keys()), "SUCH MUTANTS")
    print()

    graph = []
    label = []

    for r, data in roots.items():
        data_f = list(filter(lambda x: x[0] in ever_unkilled, data))
        d_t = list(map(lambda x:float(x[1]), data_f))
        graph.append(d_t)
        label.append(r)
        d_m = list(map(lambda x:int(x[2]), data_f))
        print (r, "# DATA POINTS:", len(d_t))
        score = len(list(filter(lambda x: x != 0, d_m))) / len(list(d_m))
        print(r, "MEAN:", round(scipy.mean(d_t), 2), "MEDIAN:", round(scipy.median(d_t), 2),
              "RANGE: [" + str(round(min(d_t), 2)) + " - " + str(round(max(d_t), 2)) + "]")
        print(r, "MUTATION SCORE:", round(score, 2))
        print()

    for r1, data1 in roots.items():
        data1_f = list(filter(lambda x: x[0] in ever_unkilled, data1))
        d_t_1 = list(map(lambda x:float(x[1]), data1_f))
        for r2, data2 in roots.items():
            if r1 < r2:
                data2_f = list(filter(lambda x: x[0] in ever_unkilled, data2))
                d_t_2 = list(map(lambda x:float(x[1]), data2_f))
                try:
                    print("Mann-Whitney U:", scipy.stats.mannwhitneyu(d_t_1, d_t_2))
                except ValueError:
                    pass

    f2 = plt.figure()
    plt.ylabel("Time(s)")
    plt.boxplot(graph, labels=label)
    pp = PdfPages("unkilled.pdf")
    pp.savefig(f2)
    pp.close()
    print("SAVED GRAPH OF DATA OVER EVER-UNKILLED MUTANTS TO unkilled.pdf")
