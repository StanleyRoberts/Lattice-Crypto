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

# In[1]:


import import_ipynb

import LWE_PKE


# Module Info
# -----------------
# To model a 'singleton' CLI object in a Pythonic way we define a module that provides a function for CLI.

# In[2]:


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


# In[3]:


def CLI(choice="y"):
    """
        A very basic linear CLI walkthrough ofan LWE interaction
        
        Parameters
        ----------
        
        choice : string
            determines if CLI is run in bitmode, a value other than the string 'y' runs CLI in full mode
    
    """
    
    if choice=="y": print("Notice! Running in bit-mode")
    print("Running LWE command-line interface for messaging from Alice to Bob\nInstanciating LWE...\n")
    
    alice = LWE_PKE.LWE(n=10)
    bob = LWE_PKE.LWE(n=10)
    
    apk = alice.getPublicKey()
    bpk = bob.getPublicKey()
    
    print("Here is Alice's public key:")
    print(apk)
    print("\n\n\nHere is Bob's public key:")
    print(bpk)
    
    print("\n\nWhat message would you like Alice to encrypt?")
    
    message = input()
    if choice=="y":
        while message not in ["0", "1"]:
            print("not a bit, please try again:")
            message = input()
        message = int(message)
        
    print("\nEncrypting message...")
    cipher = None
    if choice=="y": cipher = alice.enc(message, bpk)
    else: cipher = alice.encString()
    print("\nAlice's ciphertext:")
    print(cipher)
     
    print("\nDecrypting message...")
    plain = None
    if choice=="y": plain = bob.dec(cipher)
    else: plain = bob.decMatrix()
    print("\nBob's decrypted plaintext:")
    print(plain)
    
    print("\nMessage decrypted, terminating...")


# In[4]:


if __name__ == '__main__':
    
    print("Run CLI in bit-mode? (y/n)")
    choice = input()
    
    while (choice not in ["y", "n"]):
        print("Did not understand input, please try again:")
        choice = input()
        
    CLI(choice)
        


# In[ ]:





# In[ ]:




