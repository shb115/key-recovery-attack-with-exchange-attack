import pickle
import numpy as np
import math

result = []
for i in range(1300106, 1300120):
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
print(succ/total)
