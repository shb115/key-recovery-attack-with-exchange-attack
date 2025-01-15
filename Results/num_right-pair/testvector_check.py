from bitstring import BitArray

# AES 암호화 함수
def AES_Enc(P, K):    # P는 128bit 평문, K는 128bit 마스터키
    C_arr = []
    
    state = P    # state는 현재 상태, state는 128bit
    C_arr.append(("Input",state))
    
    RoundKey = KeyExpansion(K)    # RoundKey를 KeyExpansion 함수를 통하여 계산하여 list로 저장, RoundKey는 128bit 11개짜리 list

    state = state ^ RoundKey[0]    # AddRoundKey 과정, # state는 128bit
    C_arr.append(("0 round AK",state))

    # 라운드 수만큼 돈다
    for i in range(1, 10):
        state = SubBytes(state)    # state는 128bit
        C_arr.append(("{} round SB".format(i),state))
        state = ShiftRows(state)    # state는 128bit
        C_arr.append(("{} round SR".format(i),state))
        state = MixColumns(state)    # state는 128bit
        C_arr.append(("{} round MC".format(i),state))
        state = state ^ RoundKey[i]    # AddRoundKey 과정, state는 128bit
        C_arr.append(("{} round AK".format(i),state))

    # 마지막 라운드
    state = SubBytes(state)    # state는 128bit
    C_arr.append(("10 round SB",state))
    state = ShiftRows(state)    # state는 128bit
    C_arr.append(("10 round SR",state))
    state = state ^ RoundKey[5]    # AddRoundKey 과정, state는 128bit
    C_arr.append(("10 round AK",state))

    C = state    # 암호문 C

    return C_arr    # C는 128bit

# KeyExpansion 함수
def KeyExpansion(K):    # K는 128bit
    RoundKey = [K]
    for i in range(10):
        W0 = RoundKey[-1][  0: 32]    # 제일 최근 RoundKey를 4등분, W0는 32bit
        W1 = RoundKey[-1][ 32: 64]    # W1는 32bit
        W2 = RoundKey[-1][ 64: 96]    # W2는 32bit
        W3 = RoundKey[-1][ 96:128]    # W3는 32bit
        W3prime = W3.copy()    # W3prime은 32bit
        W3prime.ror(24)    # RotWord 과정
        W3prime = SubWord(W3prime)    # SubWord 과정
        W4 = W0 ^ Rcon[i] ^ W3prime    # W4는 32bit
        W5 = W1 ^ W4    # W5는 32bit
        W6 = W2 ^ W5    # W6는 32bit
        W7 = W3 ^ W6    # W7는 32bit
        RoundKey.append(W4 + W5 + W6 + W7)    # RoundKey에 128bit 추가
    return RoundKey    # RoundKey는 128bit 11개짜리 list

def InvKeyExpansion(K):
    RoundKey = [K]
    for i in range(9, -1, -1):
        W4 = RoundKey[-1][  0: 32]    # 제일 최근 RoundKey를 4등분, W0는 32bit
        W5 = RoundKey[-1][ 32: 64]    # W1는 32bit
        W6 = RoundKey[-1][ 64: 96]    # W2는 32bit
        W7 = RoundKey[-1][ 96:128]    # W3는 32bit
        W3 = W6 ^ W7
        W2 = W5 ^ W6
        W1 = W4 ^ W5
        W3prime = W3.copy()    # W3prime은 32bit
        W3prime.ror(24)    # RotWord 과정
        W3prime = SubWord(W3prime)    # SubWord 과정
        W0 = W4 ^ Rcon[i] ^ W3prime
        RoundKey.append(W0 + W1 + W2 + W3)
    return RoundKey[-1]

# SubWord 함수
def SubWord(data):    # data는 32bit
    result = BitArray()    # 초기화
    for byte in data.cut(8):    # data를 4등분, byte는 8bit
        result.append(Sbox[int(byte.hex, 16)])    # Sbox를 거친 후 result에 추가
    return result    # result는 32bit

# SubBytes 함수
def SubBytes(data):     # data는 128bit
    result = BitArray()    # 초기화
    for byte in data.cut(8):    # data를 16등분, byte는 8bit
        result.append(Sbox[int(byte.hex, 16)])    # Sbox를 거친 후 result에 추가
    return result    # result는 128bit

# ShiftRows 함수
def ShiftRows(data):    # data는 128bit
    result = BitArray(length = 128)   # result는 빈 메모리
    # 함수에 맞게 저장
    result[  0:  8] = data[  0:  8]
    result[  8: 16] = data[ 40: 48]
    result[ 16: 24] = data[ 80: 88]
    result[ 24: 32] = data[120:128]
    result[ 32: 40] = data[ 32: 40]
    result[ 40: 48] = data[ 72: 80]
    result[ 48: 56] = data[112:120]
    result[ 56: 64] = data[ 24: 32]
    result[ 64: 72] = data[ 64: 72]
    result[ 72: 80] = data[104:112]
    result[ 80: 88] = data[ 16: 24]
    result[ 88: 96] = data[ 56: 64]
    result[ 96:104] = data[ 96:104]
    result[104:112] = data[  8: 16]
    result[112:120] = data[ 48: 56]
    result[120:128] = data[ 88: 96]
    return result    # result는 128bit

# MixColumns 함수
def MixColumns(data):    # data는 128bit
    result = BitArray()    # result는 빈 메모리
    for column in data.cut(32):    # columns는 32bit = 1 column
        result.append(AES_Mul(2, column[ 0: 8]) ^ AES_Mul(3, column[ 8:16]) ^ column[16:24] ^ column[24:32])
        result.append(column[ 0: 8] ^ AES_Mul(2, column[ 8:16]) ^ AES_Mul(3, column[16:24]) ^ column[24:32])
        result.append(column[ 0: 8] ^ column[ 8:16] ^ AES_Mul(2, column[16:24]) ^ AES_Mul(3, column[24:32]))
        result.append(AES_Mul(3, column[ 0: 8]) ^ column[ 8:16] ^ column[16:24] ^ AES_Mul(2, column[24:32]))
    return result    #result는 128bit

def one_inv_MixColumns(column):
    result = BitArray()
    result.append(AES_Mul(0x0E, column[ 0: 8]) ^ AES_Mul(0x0B, column[ 8:16]) ^ AES_Mul(0x0D, column[16:24]) ^ AES_Mul(0x09, column[24:32]))
    result.append(AES_Mul(0x09, column[ 0: 8]) ^ AES_Mul(0x0E, column[ 8:16]) ^ AES_Mul(0x0B, column[16:24]) ^ AES_Mul(0x0D, column[24:32]))
    result.append(AES_Mul(0x0D, column[ 0: 8]) ^ AES_Mul(0x09, column[ 8:16]) ^ AES_Mul(0x0E, column[16:24]) ^ AES_Mul(0x0B, column[24:32]))
    result.append(AES_Mul(0x0B, column[ 0: 8]) ^ AES_Mul(0x0D, column[ 8:16]) ^ AES_Mul(0x09, column[16:24]) ^ AES_Mul(0x0E, column[24:32]))
    return result

# GF Multiplication
def AES_Mul(a, b):    # a는 2 또는 3, b는 8bit
    result = BitArray(length = 8)   # result는 빈 메모리
    if a & 1:   # a가 3이면 b를 xor
        result = result ^ b
    if b[0]:    # b의 최상위 비트가 1이면 x^8을 x^4 + x^3 + x + 1, 즉 0x1b을 추가적으로 xor 계산
        result = result ^ (b << 1) ^ BitArray(hex = '0x1b')
    else:    # b의 최상위 비트가 0이면 x만 곱해서 연산
        result = result ^ (b << 1)
    return result    # result는 8bit

# ShiftRows 함수
def InvShiftRows(data):    # data는 128bit
    result = BitArray(length = 128)   # result는 빈 메모리
    # 함수에 맞게 저장
    result[  0:  8] = data[  0:  8]
    result[  8: 16] = data[104:112]
    result[ 16: 24] = data[ 80: 88]
    result[ 24: 32] = data[ 56: 64]
    result[ 32: 40] = data[ 32: 40]
    result[ 40: 48] = data[  8: 16]
    result[ 48: 56] = data[112:120]
    result[ 56: 64] = data[ 88: 96]
    result[ 64: 72] = data[ 64: 72]
    result[ 72: 80] = data[ 40: 48]
    result[ 80: 88] = data[ 16: 24]
    result[ 88: 96] = data[120:128]
    result[ 96:104] = data[ 96:104]
    result[104:112] = data[ 72: 80]
    result[112:120] = data[ 48: 56]
    result[120:128] = data[ 24: 32]
    return result    # result는 128bit

# AES S box
Sbox = ['0x63', '0x7C', '0x77', '0x7B', '0xF2', '0x6B', '0x6F', '0xC5', '0x30', '0x01', '0x67', '0x2B', '0xFE', '0xD7', '0xAB', '0x76',
	'0xCA', '0x82', '0xC9', '0x7D', '0xFA', '0x59', '0x47', '0xF0', '0xAD', '0xD4', '0xA2', '0xAF', '0x9C', '0xA4', '0x72', '0xC0',
	'0xB7', '0xFD', '0x93', '0x26', '0x36', '0x3F', '0xF7', '0xCC', '0x34', '0xA5', '0xE5', '0xF1', '0x71', '0xD8', '0x31', '0x15',
	'0x04', '0xC7', '0x23', '0xC3', '0x18', '0x96', '0x05', '0x9A', '0x07', '0x12', '0x80', '0xE2', '0xEB', '0x27', '0xB2', '0x75',
	'0x09', '0x83', '0x2C', '0x1A', '0x1B', '0x6E', '0x5A', '0xA0', '0x52', '0x3B', '0xD6', '0xB3', '0x29', '0xE3', '0x2F', '0x84',
	'0x53', '0xD1', '0x00', '0xED', '0x20', '0xFC', '0xB1', '0x5B', '0x6A', '0xCB', '0xBE', '0x39', '0x4A', '0x4C', '0x58', '0xCF',
	'0xD0', '0xEF', '0xAA', '0xFB', '0x43', '0x4D', '0x33', '0x85', '0x45', '0xF9', '0x02', '0x7F', '0x50', '0x3C', '0x9F', '0xA8',
	'0x51', '0xA3', '0x40', '0x8F', '0x92', '0x9D', '0x38', '0xF5', '0xBC', '0xB6', '0xDA', '0x21', '0x10', '0xFF', '0xF3', '0xD2',
	'0xCD', '0x0C', '0x13', '0xEC', '0x5F', '0x97', '0x44', '0x17', '0xC4', '0xA7', '0x7E', '0x3D', '0x64', '0x5D', '0x19', '0x73',
	'0x60', '0x81', '0x4F', '0xDC', '0x22', '0x2A', '0x90', '0x88', '0x46', '0xEE', '0xB8', '0x14', '0xDE', '0x5E', '0x0B', '0xDB',
	'0xE0', '0x32', '0x3A', '0x0A', '0x49', '0x06', '0x24', '0x5C', '0xC2', '0xD3', '0xAC', '0x62', '0x91', '0x95', '0xE4', '0x79',
	'0xE7', '0xC8', '0x37', '0x6D', '0x8D', '0xD5', '0x4E', '0xA9', '0x6C', '0x56', '0xF4', '0xEA', '0x65', '0x7A', '0xAE', '0x08',
	'0xBA', '0x78', '0x25', '0x2E', '0x1C', '0xA6', '0xB4', '0xC6', '0xE8', '0xDD', '0x74', '0x1F', '0x4B', '0xBD', '0x8B', '0x8A',
	'0x70', '0x3E', '0xB5', '0x66', '0x48', '0x03', '0xF6', '0x0E', '0x61', '0x35', '0x57', '0xB9', '0x86', '0xC1', '0x1D', '0x9E',
	'0xE1', '0xF8', '0x98', '0x11', '0x69', '0xD9', '0x8E', '0x94', '0x9B', '0x1E', '0x87', '0xE9', '0xCE', '0x55', '0x28', '0xDF',
	'0x8C', '0xA1', '0x89', '0x0D', '0xBF', '0xE6', '0x42', '0x68', '0x41', '0x99', '0x2D', '0x0F', '0xB0', '0x54', '0xBB', '0x16']

Rcon = ['0x01000000', '0x02000000', '0x04000000', '0x08000000', '0x10000000', '0x20000000', '0x40000000', '0x80000000', '0x1b000000', '0x36000000']

def testvector():
    plaintext = BitArray(hex = '0x00000000000000000000000000000000')
    masterkey = BitArray(hex = '0x00112233445566778899aabbccddeeff')
    ciphertext = BitArray(hex = '0xfde4fbae4a09e020eff722969f83832b')
    print(AES_Enc(plaintext, masterkey) == ciphertext)

def DC_table(key):
    x1 = [i for i in range(256)]
    x2 = [0 for i in range(256)]
    y1 = [0 for i in range(256)]
    y2 = [0 for i in range(256)]
    cnt = 0
    ddt = [[0 for _ in range(256)] for __ in range(256)]
    for df in range(256):
        for i in range(256):
            x2[i] = x1[i] ^ df
        for i in range(256):
            y1[i] = int(Sbox[x1[i] ^ key], 16)
            y2[i] = int(Sbox[x2[i] ^ key], 16)
        for i in range(256):
            ddt[df][y1[i] ^ y2[i]] = ddt[df][y1[i] ^ y2[i]] + 1
    return ddt

import CipherTools as CT

testvector_ct = []
testvector_pt = []

# 파일 열기
with open('results.txt', 'r') as file:
    # 줄 단위로 읽기
    lines = file.readlines()

i=0
T=0
F=0
while i<len(lines):
    if lines[i][0]=='0':
        mk=int(lines[i][35:].rstrip(),16)
        K=BitArray(hex="0x"+hex(mk)[2:].zfill(32))
    if lines[i][:2]=='C1':
        c1=int(lines[i][5:].rstrip(),16)
        p1='0x'+CT.AES128_128_DEC(c1,mk,5,"hexstr")
        P1=BitArray(hex=p1)
        C1=AES_Enc(P1,K)
    if lines[i][:2]=='C2':
        c2=int(lines[i][5:].rstrip(),16)
        p2='0x'+CT.AES128_128_DEC(c2,mk,5,"hexstr")
        P2=BitArray(hex=p2)
        C2=AES_Enc(P2,K)
        a=C1[4][1]^C2[4][1]
        a = C1[4][1]^C2[4][1]
        a=a.tobytes()
        a=a.hex()
        if (a[:2]=="00" or a[2:4]=="00" or a[4:6]=="00" or a[6:8]=="00") and (a[8:10]=="00" or a[10:12]=="00" or a[12:14]=="00" or a[14:16]=="00"):
            T+=1
        else:
            F+=1
    i+=1

print(T/(T+F))
print(T+F)
print(T,F)

i=0
T=0
F=0
flag=1
while i<len(lines):
    if lines[i][0]=='0':
        mk=int(lines[i][35:].rstrip(),16)
        K=BitArray(hex="0x"+hex(mk)[2:].zfill(32))
        flag=1
    if lines[i][:2]=='C1':
        c1=int(lines[i][5:].rstrip(),16)
        p1='0x'+CT.AES128_128_DEC(c1,mk,5,"hexstr")
        P1=BitArray(hex=p1)
        C1=AES_Enc(P1,K)
    if flag and lines[i][:2]=='C2':
        c2=int(lines[i][5:].rstrip(),16)
        p2='0x'+CT.AES128_128_DEC(c2,mk,5,"hexstr")
        P2=BitArray(hex=p2)
        C2=AES_Enc(P2,K)
        a=C1[4][1]^C2[4][1]
        a = C1[4][1]^C2[4][1]
        a=a.tobytes()
        a=a.hex()
        if (a[:2]=="00" or a[2:4]=="00" or a[4:6]=="00" or a[6:8]=="00") and (a[8:10]=="00" or a[10:12]=="00" or a[12:14]=="00" or a[14:16]=="00"):
            T+=1
        else:
            F+=1
        flag=0
    i+=1

print(T+F)

'''
# 파일을 읽기 모드로 연다
with open('testvector_240621.txt', 'r', encoding='utf-8') as file:
    for line in file:
        if line[0]=="C":
            testvector_ct.append(int(line[5:].rstrip(),16))
        if line[:2] == "mk":
            mk=line[7:].rstrip()

mk=int(mk,16)

for i in testvector_ct:
    testvector_pt.append('0x'+CT.AES128_128_DEC(i,mk,5,"hexstr"))

K=BitArray(hex="0x"+hex(mk)[2:].zfill(32))

for i in range(0,len(testvector_pt),4):
    
    P1=BitArray(hex=testvector_pt[i])
    P2=BitArray(hex=testvector_pt[i+1])
    C1=AES_Enc(P1,K)
    C2=AES_Enc(P2,K)
    a = C1[4][1]^C2[4][1]
    a=a.tobytes()
    a=a.hex()
    if (a[:2]=="00" or a[2:4]=="00" or a[4:6]=="00" or a[6:8]=="00") and (a[8:10]=="00" or a[10:12]=="00" or a[12:14]=="00" or a[14:16]=="00"):
        print(True)
    else:
        print(False)
'''