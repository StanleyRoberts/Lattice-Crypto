#!/usr/bin/env python
# coding: utf-8

# CLI for Lattice System
# ==================
# Part of a project by Stanley Roberts on Lattice Cryptography  
# This code is a demonstration command-line interface using the LWE module
# 
# &nbsp;
# &nbsp;
# &nbsp;
# 
# Imports
# -----------

# In[ ]:


import import_ipynb

import LWE_PKE


# Module Info
# -----------------
# To model a 'singleton' CLI object in a Pythonic way we define a module that provides a function for CLI.

# In[ ]:


"""
Name
----
CLI

Description
-----------
This module implements a singleton instance of a command-line intergace
for an LWE public key encryption. It models how to use the LWE_PKE module

Contents
--------
CLI : runs a command-line interface of LWE
"""


# In[ ]:


def CLI():
    """
        A very basic linear CLI walkthrough ofan LWE interaction
        
        Parameters
        ----------
        
        choice : string
            determines if CLI is run in bitmode, a value other than the string 'y' runs CLI in full mode
    
    """
    print("Run CLI in bit-mode? (y/n)")
    choice = input()
    
    while (choice not in ["y", "n"]):
        print("Did not understand input, please try again:")
        choice = input()
    
    if choice=="y":
        print("Notice! Running in bit-mode")
        choice=False
    else: choice=True
    print("Running LWE command-line interface for messaging from Alice to Bob\nInstanciating LWE...\n")
    alice = bob = None
    alice = LWE_PKE.createLWE(n=10, mb=choice)
    bob = LWE_PKE.createLWE(n=10, mb=choice)

    apk = alice.getPublicKey()
    bpk = bob.getPublicKey()
    
    print("Here is Alice's public key:")
    print(apk)
    print("\n\n\nHere is Bob's public key:")
    print(bpk)
    
    print("\n\nWhat message would you like Alice to encrypt?")
    message = input()
    
    while not all(b in ["0", "1"] for b in message):
        print("not a bit(string), please try again:")
        message = input()
        
    print("\nEncrypting message...")
    cipher = alice.enc(message, bpk)

    print("\nAlice's ciphertext:")
    print(cipher)
     
    print("\nDecrypting message...")
    plain = bob.dec(cipher)
    print("\nBob's decrypted plaintext:")
    print(plain)
    
    input("\nMessage decrypted, Press enter to terminate...")


# In[ ]:


if __name__ == '__main__':
    CLI()


# # 
