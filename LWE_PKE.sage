#!/usr/bin/env python
# coding: utf-8

# Lattice LWE Implementation
# =======================
# 
# 
# 
# Part of a project by Stanley Roberts on Lattice Cryptography  
# This code is an implementation of *Regevs* public key cryptography mechanism using LWE

# In[1]:


#### Imports ####

from sage.stats.distributions.discrete_gaussian_integer import DiscreteGaussianDistributionIntegerSampler
import copy
import math
import random


# Module Info
# ----------
# 
# 
# All default parameters are generated as suggested in Regev's paper but can be
# smaller/different as long as they adhere to sufficient security constraints
# 
# see: 'A Framework to Select Parameters for Lattice-Based Cryptography'
# and 'Better Key Sizes (and Attacks) for LWE-Based Encryption'

# In[2]:


"""
Name
----
LWE_PKE

Description
-----------
This module implements a public key cryptography system using
LWE as detailed in Regev's paper On Lattices, Learning with Errors,
Random Linear Codes, and Cryptography

Contents
--------
publicKey : creates a public key
LWE : creates an LWE system
"""


# Helper Classes
# ---------------------
# 
# Smaller classes to assist in implementing the LWE system

# In[3]:


class publicKey:
    """
    Creates a Public Key object
    
    Uses a matrix to create an LWE public key whose rows (excluding last element)
    are the vectors Ai and the last element in each row is the corresponding Bi.
    
    Parameters
    ----------
    
    pk : sagemath matrix
        matrix to use to construct public key.
    q : int
        public key modulus
    
    """
    def __init__(self, pk, q):
        self.pk = pk
        self.q = q
    
    def getA(self, i):
        """
        Get an A vector from the public key.
        
        Parameters
        ----------
        i : int
            vector index.
        
        Returns
        -------
        sagemath vector
            the appropriate A vector.
        """
        temp = list(self.pk.row(i))
        temp.pop()
        return vector(Integers(self.q), temp)
    
    def getB(self, i):
        """
        Get a B value from the public key.
        
        Parameters
        ----------
        i : int
            value index.
        
        Returns
        -------
        int
            the appropriate B value.
        """
        temp = list(self.pk.row(i))
        return temp.pop()
    
    def getSampleNo(self):
        return self.pk.nrows()
    
    def getModulus(self):
        return self.q
    
    def __str__(self):
        return self.pk.__str__() + " mod: " + self.q.__str__()
    
class cipherText:
    '''
    Generates an LWE ciphertext pair.
    
    Parameters
    ----------
    a : sagemath vector
        vector part of pair
    b : int
        integer part of pair
    
    '''
    def __init__(self, a, b):
        self.a = a
        self.b = b
    
    def __str__(self):
        return "[" + self.a.__str__() + ", " + self.b.__str__() + "]"
    


# LWE Implementation
# -----------------------------
# 
# Main implementation of LWE PKE system with encryption and decryption

# In[4]:


class LWE:
    """
    Constructs an LWE enviroment.
    
    Constructs a new LWE enviroment based on given parameter and
    generates a public and private key for encryption and decryption.
    
    Parameters
    ----------
    n : int
        security parameter which defines dimension, defaults to 512
    q : int
        modulus, defaults to a random prime in the range of n^2 to 2n^2
    m : int
        desired number of samples for the public key, defaults to (n+1)log(q)
    x : callable object
        error distribution, defaults to a discrete gaussian with standard deviation 1/sqrt(n)log^2(n)
    """
    def __init__(self, n=512, q=None, m=None, x=None):
        self.n, self.q, self.m, self.x = n, q, m, x
        if q==None:
            self.q = random_prime(2*self.n^2, self.n^2) 
        if m==None:
            self.m = ((self.n+1)*self.q.log(prec=100)).integer_part()
        if x==None:
            alpha = (1/(sqrt(self.n)*log(self.n)^2))
            self.x = DiscreteGaussianDistributionIntegerSampler(alpha/sqrt(2*pi))
        
        self.VS = GF(self.q)^self.n #vector space, dimension n, modulus q
        self._s = self.VS.random_element() #secret key
        self._pk = self.__genPublicKey() #public key
    
    def getPublicKey(self):
        """
        Return public key associated with the LWE object
        
        Returns
        -------
        sagemath matrix
            the public key in matrix form [A, q]
        """
        return copy.deepcopy(self._pk)
    
    def __LWEsample(self):
        # gets a sample (a, b) where a is a randomly generated vector such that a ∈ VS
        # and b = <a, s> + e where e is sampled according to the error distribution
        
        a = self.VS.random_element()
        er = self.x()
        b = self._s.inner_product(a) + er
        return vector(Integers(self.q), list(a)+[b.lift()])

    def __genPublicKey(self):
        # generates a public key by combining m samples (from sampler) into a matrix form
        
        vector_list = [self.__LWEsample() for x in range(self.m)]
        return publicKey(matrix(vector_list), self.q)

    def enc(self, bit, key):
        """
        Encrypts a bit using the given key
        
        Parameters
        ----------
        bit : the binary bit to encrypt
        key : the public key to encrypt using
        
        Returns
        -------
        sagemath vector : vector composing one half of ciphertext pair (a)
        int : integer composing other half of pair (b)
        """
        
        sample_size = key.getSampleNo()
        q = key.getModulus()
        subset = Subsets(sample_size-1).random_element()
        a, b = 0, 0
        for i in subset:
            a += key.getA(i)
            b += key.getB(i)
        if bit==1:
            b += math.floor(q/2)
        return cipherText(a%q, b%q)
    
    def dec(self, pair):
        """
        Decrypts a bit which has been encrypted using the instance's public key
        
        Parameters
        ----------
        a : vector half of encryption pair
        b : integer half of encryption pair
        
        Returns
        -------
        int : decrypted bit
        
        """
        testval = lift(pair.b-pair.a.inner_product(self._s))
        compval = math.floor(self.q/2)
        
        if (min(0, compval, key = lambda x: abs(x-testval))==0): return 0
        return 1
    
    def encString(self, string):
        """
        Encrypts a string using the given key
        
        Parameters
        ----------
        string : plaintext string to encrypt
        key : public key to encrypt using
        
        Returns
        -------
        sagemath matrix : matrix whose rows correspond to a bit encryption pair
        """
        pass
    
    def decMatrix(self, a):
        """
        Decrypts a matrix whose rows each correspond to an encryption pair constructed using instance's public key
        
        Parameters
        ----------
        a : sagemath matrix to decrypt
        
        Returns
        -------
        string : plaintext string
        """
        pass


# Unit Tests
# --------------
# 
# Unit tests for module, including testing helper classes and full LWE implementation

# In[5]:


import unittest

class TestHelpers(unittest.TestCase):
    
    def test_publicKey(self): # generate some random matrix and test get functions work as expected
        m, n = (randint(1, 100) for x in range(2))
        q = random_prime(2*n^2, n^2) 
        A = random_matrix(GF(q), m, n-1)
        B = random_matrix(GF(q), m, 1)
        
        key = publicKey(block_matrix(1, 2, [A, B]), q)
        
        
        for i in range(0, m-1):
            self.assertEqual(A.row(i), key.getA(i))
            self.assertEqual(B[i, 0], key.getB(i))
            self.assertEqual(q, key.getModulus())
    
    def test_Error_publicKey(self):
        # test error for modulus more than entries
        # test error for non integer matrix or non-prime q
        pass


class TestLWE(unittest.TestCase):
    
    def test_privateMethods(self):
        pass
    
    def test_enc(self):
        pass
    
    def test_dec(self):
        pass
    
    def test_LWE(self):
        
        alice = LWE(n=150)
        bob = LWE(n=200)

        tests = 100

        success = True
        
        pk = bob.getPublicKey()
        for i in range (0, tests):
            message = randint(0, 1)
            cipher = alice.enc(message, pk)
            plain = bob.dec(cipher)
            if message != plain: success = False
            
        self.assertTrue(success)


unittest.main(argv=['-v'], verbosity=2, exit=False)

