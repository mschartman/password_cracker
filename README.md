password_cracker
================

Cracks password files that use DES or SHA-512

Usage examples:
---------------

    python password_cracker.py
    python password_cracker.py --passwords_file shadow
    python password_cracker.py --hashing_algorithm des
    python password_cracker.py --hashing_algorithm sha512
    python password_cracker.py --passwords_file shadow --hashing_algorithm des
    python password_cracker.py --passwords_file shadow --hashing_algorithm sha512

For more help run:
------------------

    python password_cracker.py --help

---

If you don't provide a passwords file, it will look for "shadow" inside of it's current working directory. If you don't provide a hashing algorithm, it will try both DES and SHA-512, in that respective order. 

While the program is running, you can press the enter key to get stats like the average attempts per second at that time, the current hashing algorithm in use, the last password attempted, and all passwords cracked so far.