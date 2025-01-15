This repository contains the implementation of the key recovery attacks presented in our paper:
- Key-Recovery Attacks on Reduced-Round AES with Exchange Attacks, Hanbeom Shin, Dongjae Lee2, Deukjo Hong3, Jaechul Sung4, Seokhie Hong.

## Generic Structure
The implementation includes three components as presented in the experiments of the paper: counting the number of detected pairs in the distinguisher, counting the number of right pairs among the detected pairs, and determining whether the key recovery attack is successful. The implementation is structured by building .dll and .so files in C, which are then used as libraries in Python. The results of the experiments are also presented.
