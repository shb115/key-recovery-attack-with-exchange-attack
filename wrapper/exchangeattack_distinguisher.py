import CipherTools as CT
import random
import numpy as np
import math
import pickle
import os
import multiprocessing as mt

for i in range(800):
    mk_len = 16
    pt_len = 16
    pt = random.randint(0, 2 ** 128 - 1)
    mk = random.randint(0, 2 ** 128 - 1)
    print('0x'+f"{pt:032x}", hex(mk))
    mk_arry = CT.int_to_cbytes(mk, mk_len)
    pt_arry = CT.int_to_cbytes(pt, pt_len)    
    CT.EXCHANGE_DISTINGUISHER(mk_arry, pt_arry, 5)