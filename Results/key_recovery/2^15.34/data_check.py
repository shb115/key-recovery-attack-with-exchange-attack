import pickle
import numpy as np
import math
from scipy.stats import poisson

result = []
for i in range(1334069, 1334083):
    try:
        f = open("exchangeattack_keyrecovery_result%d.pickle"%(i), "rb")
    except:
        continue

    while True:
        try:
            result.append(pickle.load(f))
        except EOFError:
            break
    f.close()

total=len(result)
succ=0
fail=0
non=0

for i in result:
    if i==0: fail+=1
    elif i==1: succ+=1
    else: non+=1

print(total)
print(succ)
print(fail)
print(non)
print((succ+fail)/total)
print(succ/total)

from scipy.stats import poisson

# 람다 값 (평균 발생 횟수)
lambda_val = 3

# PMF: P(X = k)
k = 9
probability_exact = poisson.pmf(k, mu=lambda_val)
print(f"P(X = {k}) = {probability_exact}")

# CDF: P(X <= k)
k = 9
probability_cumulative = poisson.cdf(k, mu=lambda_val)
print(f"P(X <= {k}) = {probability_cumulative}")

# Survival Function: P(X >= k)
k = 3
probability_survival = poisson.sf(k-1, mu=lambda_val)  # sf(k-1) = 1 - cdf(k-1)
print(f"P(X >= {k}) = {(probability_survival)}")
print(f"succ prob = {(probability_survival)*(((2**-176)/(2**-176+(2**-188)*(1-2**-176))))**3}")

