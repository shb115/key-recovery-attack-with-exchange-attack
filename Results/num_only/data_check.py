import pickle
import numpy as np
import math

result = []
for i in range(427077, 469919):
    try:
        f = open("exchangeattack_result%d.pickle"%(i), "rb")
    except:
        continue

    while True:
        try:
            result.append(pickle.load(f))
        except EOFError:
            break
    f.close()
print(len(result))
cnt=[]
for i in result:
    cnt.append(i[2])
print(sum(cnt)/len(cnt))
print(min(cnt),max(cnt))

counter=[0 for _ in range(8)]

for i in cnt:
    counter[i]+=1

print(counter)

import matplotlib.pyplot as plt

# 데이터
categories = ['0', '1', '2', '3', '4', '5', '6', '7']
values = counter

# 막대 그래프 생성
plt.bar(categories, values)

# 제목과 레이블 추가
plt.xlabel('Number of pairs')
plt.ylabel('Count of occurrence')

# 그래프 표시
plt.show()