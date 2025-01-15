from ctypes import *
import struct
from sys import platform
from sys import version_info
import datetime
import os
import codecs
import math

import numpy as np

__SYSTEM_BIT    = struct.calcsize("P") * 8
__THIS_FILE_DIR = os.path.dirname(os.path.realpath(__file__))
__PYTHON_VER    = version_info.major
 
if __SYSTEM_BIT == 64: #64bit
    __LIB_PATH = os.path.join(__THIS_FILE_DIR, "..", "CipherTools","x64","Release")
else: #32bit
    __LIB_PATH = os.path.join(__THIS_FILE_DIR, "..", "CipherTools","x86","Release")


if platform == "linux" or platform == "linux2":
    # Linux..
    libciphers = CDLL(os.path.join(__LIB_PATH, 'libciphertools.so'))
elif platform == "win32":
    # Windows...
    libciphers = CDLL(os.path.join(__LIB_PATH, 'libciphertools.dll'))


# list of blockciphers
BLKCIPHERS_LIST = [
    'AES128_128_ENC',
    'AES128_128_DEC',
    'AES128_192_ENC',
    'AES128_192_DEC',
    'AES128_256_ENC',
    'AES128_256_DEC',
    ]

#set the functions
for c in BLKCIPHERS_LIST:
    exec(c.lower() + " = libciphers['" + c + "']")
                                #Ciphertext      #Plaintext       #MasterKey       #Round
    exec(c.lower() + ".argtypes=POINTER(c_ubyte),POINTER(c_ubyte),POINTER(c_ubyte),c_int32")
    exec(c.lower() + ".restype=c_int")


##################
def int_to_bytes(int_data, data_len):
    if __PYTHON_VER == 3: #python 3.x
        return int_data.to_bytes(data_len, byteorder='big', signed = False)
    else: #python2.x
        rst = bytearray()
        for idx in range(data_len): #from right(big endian)
            rst.append(int_data & 0xff)
            int_data = int_data >> 8
        return rst

def bytes_to_int(bytes_data):
    if __PYTHON_VER == 3: #python 3.x
        return int.from_bytes(bytes_data, byteorder = 'big', signed=False)
    else: #python 2.x
        return int(codecs.encode(bytes_data, 'hex'), 16)
###################

###################
def int_to_cbytes(int_data, data_len):
    cbytes = (c_ubyte * data_len)()
    tmp = int_data
    for idx in range(data_len - 1, -1, -1):
        cbytes[idx] = (tmp & 0xff)
        tmp = tmp >> 8
    return cbytes

def cbytes_to_int(cbytes_data):
    tmp = bytes(cbytes_data)
    return bytes_to_int(tmp)

def cbytes_buf(data_len):
    return (c_ubyte*data_len)()
###################

###################
def byte_to_cint(byte_data, data_len):
    cint = (c_int * data_len)()
    tmp = byte_data
    for idx in range(0, data_len):
        cint[idx] = (tmp[idx] & 0xff)
    return cint
###################

###################
def int_to_binstr(int_data, bitsize):
    return format(int_data, 'b').zfill(bitsize)

def int_to_hexstr(int_data, bitsize):
    return format(int_data, 'X').zfill(int(math.ceil(bitsize/4)))
####################

def print_out_opt(ct_arry, ct_len, output_opt = 'int'):
    ct_int   = cbytes_to_int(ct_arry)
    ct_bytes = bytes(ct_arry)
    opt = output_opt.lower()
    if opt == 'int':
        return ct_int
    elif opt== 'bytes':
        return ct_bytes
    elif opt == 'cbytes':
        return ct_arry
    elif opt == 'hexlist':
        return list(ct_bytes)
    elif opt == 'binstr':
        return int_to_binstr(ct_int, ct_len*8)
    elif opt == 'hexstr':
        return int_to_hexstr(ct_int, ct_len*8)
    else:
        print(
        '''\
# output_opt must be one of the following options
# 'int'    : 136792598789324718765670228683992083246
# 'bytes'  : b'f\\xe9K\\xd4\\xef\\x8a,;\\x88L\\xfaY\\xca4+.'
# 'cbytes' : <CipherTools.c_ubyte_Array_16 object at 0x000001994C70B3C8>
# 'hexlist': [102, 233, 75, 212, 239, 138, 44, 59, 136, 76, 250, 89, 202, 52, 43, 46]
# 'binstr' : '01100110111010010100101111010100111011111000101000101100001110111000100001001100111110100101100111001010001101000010101100101110'
# 'hexstr' : '66e94bd4ef8a2c3b884cfa59ca342b2e' '''
        )
        return False



AES128_128_NUM_ROUND = 10
def AES128_128_ENC(pt=None, mk=None, round=AES128_128_NUM_ROUND, output_opt = 'int'):
    pt_len = 16
    mk_len = 16
    if pt==None or mk==None:
        return (pt_len, mk_len) #Out The Info
    ct_len = pt_len
    ##Set Into
    
    pt_arry = int_to_cbytes(pt, pt_len)
    mk_arry = int_to_cbytes(mk, mk_len)
    ct_arry = cbytes_buf(ct_len)

    aes128_128_enc(ct_arry, pt_arry, mk_arry, round)
    
    return print_out_opt(ct_arry, ct_len, output_opt)

def AES128_128_DEC(ct=None, mk=None, round=AES128_128_NUM_ROUND, output_opt = 'int'):
    ct_len = 16
    mk_len = 16
    if ct==None or mk==None:
        return (ct_len, mk_len) #Out The Info
    pt_len = ct_len
    ##Set Into
    
    ct_arry = int_to_cbytes(ct, ct_len)
    mk_arry = int_to_cbytes(mk, mk_len)
    pt_arry = cbytes_buf(pt_len)

    aes128_128_dec(pt_arry, ct_arry, mk_arry, round)

    return print_out_opt(pt_arry, pt_len, output_opt)


AES128_192_NUM_ROUND = 12
def AES128_192_ENC(pt=None, mk=None, round=AES128_192_NUM_ROUND, output_opt = 'int'):
    pt_len = 16
    mk_len = 24
    if pt==None or mk==None:
        return (pt_len, mk_len) #Out The Info
    ct_len = pt_len
    ##Set Into
    
    pt_arry = int_to_cbytes(pt, pt_len)
    mk_arry = int_to_cbytes(mk, mk_len)
    ct_arry = cbytes_buf(ct_len)

    aes128_192_enc(ct_arry, pt_arry, mk_arry, round)
    
    return print_out_opt(ct_arry, ct_len, output_opt)

def AES128_192_DEC(ct=None, mk=None, round=AES128_192_NUM_ROUND, output_opt = 'int'):
    ct_len = 16
    mk_len = 24
    if ct==None or mk==None:
        return (ct_len, mk_len) #Out The Info
    pt_len = ct_len
    ##Set Into
    
    ct_arry = int_to_cbytes(ct, ct_len)
    mk_arry = int_to_cbytes(mk, mk_len)
    pt_arry = cbytes_buf(pt_len)

    aes128_192_dec(pt_arry, ct_arry, mk_arry, round)
    
    return print_out_opt(pt_arry, pt_len, output_opt)

AES128_256_NUM_ROUND = 14
def AES128_256_ENC(pt=None, mk=None, round=AES128_256_NUM_ROUND, output_opt = 'int'):
    pt_len = 16
    mk_len = 32
    if pt==None or mk==None:
        return (pt_len, mk_len) #Out The Info
    ct_len = pt_len
    ##Set Into
    
    pt_arry = int_to_cbytes(pt, pt_len)
    mk_arry = int_to_cbytes(mk, mk_len)
    ct_arry = cbytes_buf(ct_len)

    aes128_256_enc(ct_arry, pt_arry, mk_arry, round)
    
    return print_out_opt(ct_arry, ct_len, output_opt)

def AES128_256_DEC(ct=None, mk=None, round=AES128_256_NUM_ROUND, output_opt = 'int'):
    ct_len = 16
    mk_len = 32
    if ct==None or mk==None:
        return (ct_len, mk_len) #Out The Info
    pt_len = ct_len
    ##Set Into
    
    ct_arry = int_to_cbytes(ct, ct_len)
    mk_arry = int_to_cbytes(mk, mk_len)
    pt_arry = cbytes_buf(pt_len)

    aes128_256_dec(pt_arry, ct_arry, mk_arry, round)
    
    return print_out_opt(pt_arry, pt_len, output_opt)

###Add ciphers below



#....

def EXCHANGE_DISTINGUISHER_NUM_ONLY(mk, pt, r):
    found_pairs = (c_ulonglong * 1)()
    found_pairs[0] = 0
    libciphers.EXCHANGE_DISTINGUISHER_NUM_ONLY(mk, pt, r, found_pairs)
    found_pairs = np.uint64(found_pairs)
    return found_pairs[0]

def EXCHANGE_DISTINGUISHER(mk, pt, r):
    libciphers.EXCHANGE_DISTINGUISHER(mk, pt, r)
    return

libciphers.EXCHANGE_KEY_RECOVERY.restype = c_uint64

def EXCHANGE_KEY_RECOVERY(mk,pt,r):    
    return libciphers.EXCHANGE_KEY_RECOVERY(mk,pt,r)

####

if __name__ == "__main__":
    aes = AES128_128_ENC(pt = 0, mk = 0, round = 10, output_opt='hexstr')
    print(aes)
    #time check
    
