import CipherTools as CT
import random
import numpy as np
import math
import pickle
import os
import multiprocessing as mt

mk_len = 16
pt_len = 16

def worker(idx_tup):
    pid = os.getpid()
    
    pt = random.randint(1, 2 ** 128 - 1)
    mk = random.randint(1, 2 ** 128 - 1)
    print('0x'+f"{pt:032x}", hex(mk))
    mk_arry = CT.int_to_cbytes(mk, mk_len)
    pt_arry = CT.int_to_cbytes(pt, pt_len)    
    result = CT.EXCHANGE_KEY_RECOVERY(mk_arry, pt_arry, 5)
    if result==1: print("Succ")
    elif result==0: print("Fail")
    else: print("No nine pairs", result)
    f = open("exchangeattack_keyrecovery_result%s.pickle"%(pid), "ab")
    pickle.dump(result, f)
    f.close()
    return

workload = [ [i] for i in range(1000)]

with mt.Pool(15) as p:
    p.map(worker, workload)