#!/usr/bin/env python
# coding: utf-8

# Lattice LWE Implementation
# =======================
# ---
# 
# 
# Part of a project by Stanley Roberts on Lattice Cryptography  
# This code is an implementation of *Regevs* public key cryptography mechanism using LWE



#### Imports ####

from sage.stats.distributions.discrete_gaussian_integer import DiscreteGaussianDistributionIntegerSampler
import copy


# Module Info
# ----------
# 
# 
# All default parameters are generated as suggested in Regev's paper but can be
# smaller/different as long as they adhere to sufficient security constraints
# 
# see: 'A Framework to Select Parameters for Lattice-Based Cryptography'
# and 'Better Key Sizes (and Attacks) for LWE-Based Encryption'



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
# Smaller classes to assist in creates the LWE system



class publicKey:
    """
    Creates a Public Key object
    
    Uses a matrix to create an LWE public key whose rows (excluding last element)
    are the vectors Ai and the last element in each row is the corresponding Bi.
    
    Parameters
    ----------
    
    pk : sagemath matrix
        matrix to use to construct public key.
    """
    def __init__(self, pk, q):
        self.pk = pk
        self.q = q
    
    def getA(self, i):
        """
        Get an A vector from the public key.
        
        Paramters
        ---------
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
        
        Paramters
        ---------
        i : int
            value index.
        
        Returns
        -------
        int
            the appropriate B value.
        """
        temp = list(self.pk.row(i))
        return temp.pop()


# LWE Implementation
# -----------------------------
# 
# Main implementation of LWE PKE system with encryption and decryption



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
            alpha = self.q * (1/(sqrt(self.n)*log(self.n)^2))
            x = DiscreteGaussianDistributionIntegerSampler(alpha/sqrt(2*pi))
        
        self.VS = GF(self.q)^self.n #vector space, dimension n, modulus q
        self._s = self.VS.random_element() #secret key
        self._pk = self.__genPublicKey(self._s, self.q) #public key
    
    def getPublicKey(self):
        """
        Return public key associated with the LWE object
        
        Returns
        -------
        sagemath matrix
            the public key in matrix form [A, q]
        """
        return copy.deepcopy(self._pk)
    
    def __LWEsample(self, s):
        # gets a sample (a, b) where a is a randomly generated vector such that a ∈ VS
        # and b = <a, s> + e where e is sampled according to the error distribution
        
        a = self.VS.random_element()
        er = self.x()
        b = self.s.inner_product(a) + er
        return vector(Integers(self.q), list(a)+[b.lift()])

    def __genPublicKey(self, s):
        # generates a public key by combining m samples (from sampler) into a matrix form
        
        vector_list = [LWEsample(s) for x in range(self.m)]
        return publicKey(matrix(vector_list))

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
        sample_size = key.nrows()
        subset = Subsets(sample_size-1).random_element()
        a, b = 0, 0
        for i in subset:
            a += key.getA(i)
        if bit==0:
            pass
        elif bit==1:
            pass
        else:
            raise ValueError("bit is non-binary").with_traceback(tracebackobj)
        return a, b%q
    
    def dec(self, a, b):
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
        pass
    
    def encString(self, string):
        """
        Encrypts a string using the given key
        
        Parameters
        ----------
        string : plaintext string to encrypt
        key : public key to encrypt using
        
        Returns
        -------
        sagemath mastrix : matrix whose rows correspond to a bit encryption pair
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





