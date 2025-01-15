import CipherTools as CT
import random
import numpy as np
import math
import pickle
import os
import multiprocessing as mt

def worker(idx_tup):
    pid = os.getpid()
    
    in_ind1 = [0, 5, 10, 15]
    in_ind2 = [3, 4, 9, 14]
    in_arry1 = CT.byte_to_cint(in_ind1, 4)
    in_arry2 = CT.byte_to_cint(in_ind2, 4)
    CT.SETTING_TDC_INFO(in_arry1, in_arry2)
    mk_len = 16
    pt_len = 16
    pt = random.randint(1, 2 ** 128 - 1)
    mk = random.randint(1, 2 ** 128 - 1)
    print(hex(pt), hex(mk))
    mk_arry = CT.int_to_cbytes(mk, mk_len)
    pt_arry = CT.int_to_cbytes(pt, pt_len)    
    cnt = CT.AES128_128_TDC_CHECK_NUM_ONLY(mk_arry, pt_arry, 5)
    print('#####')
    print("future cnt : ", cnt)
    print('#####')
    f = open("exchangeattack_result%s.pickle"%(pid), "ab")
    data = [pt, mk, cnt]
    pickle.dump(data, f)
    f.close()
    return

workload = [ [i] for i in range(1000)]

with mt.Pool(4) as p:
    p.map(worker, workload)