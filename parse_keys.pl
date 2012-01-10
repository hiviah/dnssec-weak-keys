#!/usr/bin/perl -n
#usage: ./parse_keys.pl < fetch_dnskey.log > domain_dnskeys

if (/INFO DNSKEY/) {s/^.*?INFO DNSKEY ([a-zA-Z0-9.-]+ \S+ \S+ \S+).*/$1/; print;}
