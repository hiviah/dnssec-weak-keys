#!/usr/bin/env python

#arg1 - keys file

import sys

from hashlib import sha1

weak1024 = set([line.rstrip() for line in file("openssl-blacklist/blacklist.RSA-1024") if not line.startswith("#")])
weak2048 = set([line.rstrip() for line in file("openssl-blacklist/blacklist.RSA-2048") if not line.startswith("#")])



keys_file = file(sys.argv[1])

for line in keys_file:
    domain, key_type, exponent, modulus = line.rstrip().split(" ")
    
    mod_to_hash = "Modulus="+modulus.lstrip("0").upper()+"\n"
    mod_hash = sha1(mod_to_hash).hexdigest()
    to_check = mod_hash[20:]

    #let's just check both weak1024 and weak2048 blacklists without worrying
    #about the modulus length
    for blacklist in [weak1024, weak2048]:
        if to_check in blacklist:
            print "Domain %s found with modulus %s" % (domain, modulus)
