#!/usr/bin/env python

import re
import sys
import time
import crypt
import string
import select
import argparse
from itertools import combinations_with_replacement

# Crypt's SHA-512 is not supported on all platforms, so also try importing passlib if it's installed
try:
    from passlib import hash
    imported_passlib = True
except ImportError:
    imported_passlib = False

attempts = 0
start = time.time()
last_attempt = ''
cracked = set()
current_algo = ''

def add_to_cracked(password, shadow_line):
    global cracked
    password = password[:8]
    username = shadow_line[0]
    cracked.add((password, username))

def get_digest(password, salt, algo):
    if algo == 'des':
        return crypt.crypt(password, salt)
    if algo =='sha512':
        if sys.platform == 'linux2':
            return crypt.crypt(password, '$6$' + salt + '$')
        else:
            if imported_passlib:
                return hash.sha512_crypt.encrypt(password, salt=salt, rounds=5000, implicit_rounds=True)[20:]
    print 'Error: No support for "%s".' % algo
    sys.exit(1)

def search_in(iterable, algo, numbers=False, reverse=False, first_upper=False):
    global attempts
    global last_attempt

    for line in iterable:
        attempts += 1

        # Finalize attempt
        word = line.strip()
        if reverse:
            word = word[::-1]
        if word and first_upper:
            word = (word[0].upper()+word[1:])

        last_attempt = word

        for match in (des_matches if algo == 'des' else sha512_matches):

            # Print current stats when enter is pressed
            i,o,e = select.select([sys.stdin],[],[],0)
            for s in i:
                if s == sys.stdin:
                    print 'Average attempts per second: %s' % str(attempts/(time.time()-start))
                    print 'Current algorithm: %s' % current_algo
                    print 'Last attempt: %s' % last_attempt
                    print 'Cracked So Far:'
                    for c in cracked:
                        print 'Username: %s   Password: %s' % (c[1], c[0])
                    sys.stdin.readline()

            digest = match[1] if algo == 'des' else match[2]
            salt = match[2] if algo == 'des' else match[1]

            if get_digest(word, salt, algo) == digest:
                attempts += 1
                add_to_cracked(word, match)
            elif numbers:
                use_range = 102
                if len(word) >= 8:
                    continue
                elif len(word) == 7:
                    use_range = 10
                for num in range(use_range):
                    attempts += 1
                    if get_digest(word+str(num), salt, algo) == digest:
                        add_to_cracked(word+str(num), match)
                        break
                    elif get_digest(str(num)+word, salt, algo) == digest:
                        add_to_cracked(str(num)+word, match)
                        break
                if get_digest('1337'+word, salt, algo) == digest:
                    attempts += 1
                    add_to_cracked('1337'+word, match)
                elif get_digest(word+'1337', salt, algo) == digest:
                    attempts += 1
                    add_to_cracked(word+'1337', match)

def run_crack():
    global current_algo

    for algo in algos:
        current_algo = algo

        search_in(leet_passwords, algo)

        # This is a small list so try all mutations of it first
        # Don't do this if the accounts list is massive. Or just re-implement...
        search_in(account_names, algo)
        search_in(account_names, algo, numbers=True)
        search_in(account_names, algo, reverse=True)
        search_in(account_names, algo, first_upper=True)
        search_in(account_names, algo, numbers=True, reverse=True)
        search_in(account_names, algo, numbers=True, first_upper=True)
        search_in(account_names, algo, reverse=True, first_upper=True)
        search_in(account_names, algo, numbers=True, reverse=True, first_upper=True)

        # From here on, try anything sensible
        # The english words list has no duplicates from previous lists
        search_in(top10000_passwords, algo)
        search_in(top10000_words, algo)
        search_in(english_words, algo)

        search_in(top10000_words, algo, numbers=True)
        search_in(english_words, algo, numbers=True)

        search_in(top10000_passwords, algo, reverse=True)
        search_in(top10000_words, algo, reverse=True)
        search_in(english_words, algo, reverse=True)

        search_in(top10000_passwords, algo, first_upper=True)
        search_in(top10000_words, algo, first_upper=True)
        search_in(english_words, algo, first_upper=True)

        search_in(top10000_words, algo, numbers=True, reverse=True)
        search_in(english_words, algo, numbers=True, reverse=True)
        search_in(top10000_words, algo, numbers=True, first_upper=True)
        search_in(english_words, algo, numbers=True, first_upper=True)
        search_in(top10000_words, algo, reverse=True, first_upper=True)
        search_in(english_words, algo, reverse=True, first_upper=True)

        search_in(top10000_words, algo, numbers=True, reverse=True, first_upper=True)
        search_in(english_words, algo, numbers=True, reverse=True, first_upper=True)

    # This will take a while, start over with DES
    for algo in algos:
        current_algo = algo
        for c in combinations_with_replacement(char_set, 8):
            attempt = ''.join(c)
            search_in([attempt], algo)

    print
    print 'Cracked Passwords:'
    print cracked

if __name__ == '__main__':
    
    ########## Parse command line arguments ##########
    parser = argparse.ArgumentParser(description='Crack passwords from a passwords file.')
    parser.add_argument('--passwords_file', help='the file with the password hashes, e.g. /etc/shadow', default='shadow')
    parser.add_argument('--hashing_algorithm', help='hashing algorithm to use, e.g. "des", "sha512"', default=['des', 'sha512'])
    args = parser.parse_args()

    password_file = args.passwords_file
    algos = args.hashing_algorithm if isinstance(args.hashing_algorithm, list) else [args.hashing_algorithm]
    ##################################################

    ########## Build a character set for last ditch brute forcing ##########
    char_set = list(string.ascii_letters + string.digits + string.punctuation)
    ########################################################################

    ########## Grab account names, salts, and password hashes from shadow file ##########
    DES_MATCH = re.compile(r'(?P<account_name>[\w\d_]+):(?P<hash>(?:(?P<salt>[\w\d+/]+)\.)?[\w\d+/.]+):\d+:\d+:\d+:\d+')
    SHA512_MATCH = re.compile(r'(?P<account_name>[\w\d_]+):\$6\$(?P<salt>[\w\d+/]+)\$(?P<hash>[\w\d+/.]+):\d+:\d+:\d+:\d+')

    try:
        with open(password_file, 'r') as shadow_file:
            shadow = shadow_file.read()
    except IOError:
        print 'Error: Passwords file does not exist.'
        sys.exit(1)

    des_matches = re.findall(DES_MATCH, shadow)
    sha512_matches = re.findall(SHA512_MATCH, shadow)

    print
    print 'DES Matches:'
    for match in des_matches:
        print match
    print
    print 'SHA-512 Matches:'
    for match in sha512_matches:
        print match
    print

    account_names = [a[0] for a in des_matches + sha512_matches]
    #####################################################################################

    ########## Read wordlists into memory ##########
    with open('leet_passwords.txt', 'r') as leet_passwords_file:
        leet_passwords = leet_passwords_file.readlines()
    with open('top10000_passwords.txt', 'r') as top10000_passwords_file:
        top10000_passwords = top10000_passwords_file.readlines()
    with open('top10000_words.txt', 'r') as top10000_words_file:
        top10000_words = top10000_words_file.readlines()
    with open('english_words.txt', 'r') as english_words_file: # no duplicates from previous lists
        english_words = english_words_file.readlines()
    ################################################

    try:
        run_crack()
    except KeyboardInterrupt:
        sys.exit(0)
