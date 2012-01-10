#!/usr/bin/env python

import sys
from math import log, ceil

b1024 = 1<<1024
b1023 = 1<<1023
min_exponent = 65537

for line in sys.stdin:
    try:
        domain, sig_algo, exponent_str, modulus_str = line.rstrip().split(" ")
        exponent = int(exponent_str, 16)
        modulus = int(modulus_str, 16)

        if modulus < b1023:
            print "%s - Weak %s key, bits: %d, key start: %s" % (domain, sig_algo, int(ceil(log(modulus, 2))), modulus_str[:8])
        if exponent < min_exponent:
            print "%s - Weak exponent: %d, %s key" % (domain, exponent, sig_algo)
    except:
        print >> sys.stderr, "Invalid line:", line

