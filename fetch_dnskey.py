#!/usr/bin/env python

#   This file is part of the Perspectives Notary Server
#
#   Copyright (C) 2011 Ondrej Mikle, CZ.NIC Labs
#
#   This program is free software: you can redistribute it and/or modify
#   it under the terms of the GNU General Public License as published by
#   the Free Software Foundation, version 3 of the License.
#
#   This program is distributed in the hope that it will be useful,
#   but WITHOUT ANY WARRANTY; without even the implied warranty of
#   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#   GNU General Public License for more details.
#
#   You should have received a copy of the GNU General Public License
#   along with this program.  If not, see <http://www.gnu.org/licenses/>.

import time
import sys
import threading
import Queue
import logging
import struct

from binascii import hexlify
from unbound import ub_ctx, RR_CLASS_IN, RR_TYPE_DNSKEY

class RSAKey:

	def __init__(self, exponent, modulus, digest_algo, key_purpose):
		self.exponent = exponent
		self.modulus = modulus
		self.digest_algo = digest_algo
		self.key_purpose = key_purpose

class DnskeyScanThread(threading.Thread):

	def __init__(self, task_queue, ta_file): 
		self.task_queue = task_queue
		threading.Thread.__init__(self)
		
		self.resolver = ub_ctx()
		self.resolver.resolvconf("/etc/resolv.conf")
		self.resolver.add_ta_file(ta_file) #read public keys for DNSSEC verification

	def get_rsa_keys(self, domain):
		status, result = self.resolver.resolve(domain, RR_TYPE_DNSKEY, RR_CLASS_IN)
		keys = []
		
		if status == 0 and result.havedata:
			for key in result.data.data:
				flags = struct.unpack("!H", key[:2])[0]
				proto = ord(key[2])
				algo = ord(key[3])
				pubkey = key[4:]
				
				if algo not in [1, 5] or proto != 3: #RSA/MD5 and RSA/SHA1, must be DNSSEC protocol
					continue

				#stupid RFC 2537/3110 exponent length encoding
				exp_len0 = ord(pubkey[0])
				if exp_len0 > 0:
					exp_len = exp_len0
					exp_hdr_len = 1
				else:
					exp_len = ord(pubkey[1]) << 8 + ord(pubkey[2])
					exp_hdr_len = 3

				exponent = pubkey[exp_hdr_len:exp_hdr_len + exp_len]
				modulus  = pubkey[exp_hdr_len + exp_len:]
				if algo == 1:
					digest_algo = "RSA-MD5"
				else:
					digest_algo = "RSA-SHA1"

				if flags == 257:
				    	key_purpose = "KSK"
				elif flags == 256:
					key_purpose = "ZSK"
				else:
				    	key_purpose = "?SK_%04x" % flags #for revoked bit and other reserved bits

				keys.append(RSAKey(exponent, modulus, digest_algo, key_purpose))

		return keys

	def run(self):
		while True:
			domain = self.task_queue.get()
			
			try:
				keys = self.get_rsa_keys(domain)
				if keys:
					for key in keys:
						logging.info("DNSKEY %s %s:%s %s %s", \
						  domain, key.key_purpose, key.digest_algo, \
						  hexlify(key.exponent), hexlify(key.modulus)
						  )
			except Exception:
				logging.exception("Failed to fetch keys for %s", domain)
				
			self.task_queue.task_done()


if len(sys.argv) != 4: 
	print >> sys.stderr, "ERROR: usage: <domain_file> <ta_file> <thread_count>" 
	sys.exit(1)
	
domain_file = file(sys.argv[1])
ta_file = sys.argv[2]
thread_count = int(sys.argv[3])

logging.basicConfig(filename="fetch_dnskey.log", level=logging.DEBUG,
	format="%(asctime)s %(levelname)s %(message)s [%(pathname)s:%(lineno)d]")

task_queue = Queue.Queue(5000)

for i in range(thread_count):
	t = DnskeyScanThread(task_queue, ta_file)
	t.setDaemon(True)
	t.start()

start_time = time.time()
domain_count = 0

for line in domain_file:
	domain = line.rstrip()
	task_queue.put(domain)
	domain_count += 1
	
task_queue.join()

logging.info("Fetch of dnskeys for %d domains took %.2f seconds", domain_count, time.time() - start_time)
