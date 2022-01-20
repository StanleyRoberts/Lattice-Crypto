#!/usr/bin/env python
# coding: utf-8

# Lattice LWE Implementation
# =======================
# Part of a project by Stanley Roberts on Lattice Cryptography  
# This code is an implementation of *Regevs* public key cryptography mechanism using LWE
# 
# &nbsp;
# &nbsp;
# &nbsp;
# 
# Imports
# -----------
# To support modularization we explicitly import the sage functions we use, rather than relying on the sage interpreter to resolve them

# In[ ]:


import copy
import math
import random
import unittest

from sage.stats.distributions.discrete_gaussian_integer import DiscreteGaussianDistributionIntegerSampler
from sage.modules.free_module_element import vector
from sage.functions.other import sqrt
from sage.arith.misc import random_prime
from sage.functions.log import log
from sage.symbolic.constants import pi
from sage.rings.finite_rings.finite_field_constructor import GF
from sage.matrix.constructor import matrix
from sage.combinat.subset import Subsets
from sage.rings.finite_rings.integer_mod_ring import Integers
from sage.misc.functional import lift


# Module Info
# -----------------
# 
# 
# All default parameters are generated as suggested in Regev's paper but can be
# smaller/different as long as they adhere to sufficient security constraints
# 
# see: 'A Framework to Select Parameters for Lattice-Based Cryptography'
# and 'Better Key Sizes (and Attacks) for LWE-Based Encryption'

# In[ ]:


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
publicKey : Public key data type for LWE
LWE : object representing an LWE system
cipherText : An LWE ciphertext of form (a, b) where a is a vector and b an integer
"""


# Helper Classes
# ---------------------
# 
# Smaller classes to assist in implementing the LWE system

# In[ ]:


class publicKey:
    """
    Represents a Public Key object
    
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
        self.pk = matrix(GF(q), pk.nrows(), pk.ncols(), list(pk))
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
    
    def getSampleNo(self): return self.pk.nrows()
    
    def getModulus(self): return self.q
    
    def __str__(self): return self.pk.__str__() + " mod: " + self.q.__str__()
    
class publicKey_amort(publicKey):
    """
    Represents an amortised Public Key object
    
    Creates an LWE amortised public key consisting of two matrices A and P
    
    Parameters
    ----------
    
    a : sagemath matrix
        A matrix for public key.
    p : sagemath matrix
        P matrix for public key.
    q : int
        public key modulus
    
    """
    def __init__(self, a, p, q):
        self.a, self.b, self.q = a, p, q
        
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
        return self.a.T.row(i)
        
    def getB(self, i):
        """
        Get a B vector from the public key.
        
        Parameters
        ----------
        i : int
            vector index.
        
        Returns
        -------
        sagemath vector
            the appropriate B vector.
        """
        return self.b.row(i)
    
    def getSampleNo(self): return self.b.ncols()
    
    def getL(self): return self.b.ncols()
    
    def __str__(self):
        return self.a.__str__() + "\n\n" + self.b.__str__() + " mod: " + self.q.__str__()
    
class cipherText:
    '''
    Represents an LWE ciphertext pair.
    
    Parameters
    ----------
    a : sagemath vector
        vector part of pair
    b : sagemath vector
        integer part of pair, or vector for an amortized ciphertext
    
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

# In[ ]:


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
            self.q = random_prime((2*self.n**2), True, (self.n**2)) 
        if m==None:
            self.m = ((self.n+1)*self.q.log(prec=100)).integer_part()
        if x==None:
            alpha = (1/(sqrt(self.n)*log(self.n)**2))
            self.x = DiscreteGaussianDistributionIntegerSampler(alpha/sqrt(2*pi))
        
        self.VS = GF(self.q)**self.n #vector space, dimension n, modulus q
        self._s = self.VS.random_element() #secret key
        self._pk = self.__genPublicKey() #public key
    
    def getPublicKey(self):
        """
        Return public key associated with the LWE object
        
        Returns
        -------
        publicKey
            the public key in matrix form [A|b]
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
        cipherText
            object containing vector a, and integer b which represents ciphertext of a bit)
        """
        bit = str(bit)
        if bit not in ["1", "0"]:
            raise ValueError("Not a single bit value")
        
        sample_size = key.getSampleNo()
        q = key.getModulus()
        subset = Subsets(sample_size-1).random_element()
        a, b = 0, 0
        for i in subset:
            a += key.getA(i)
            b += key.getB(i)
        if bit=="1":
            b += math.floor(q/2)
            
        return cipherText(a%q, b%q)
    
    def dec(self, pair):
        """
        Decrypts a bit which has been encrypted using the instance's secret key
        
        Parameters
        ----------
        pair : ciphertext object for an encrypted bit
        
        Returns
        -------
        int
            decrypted bit
        """
        testval = lift(pair.b-pair.a.inner_product(self._s))
        compval = math.floor(self.q/2)
        
        if (min(0, compval, key = lambda x: abs(x-testval))==0): return 0
        return 1
    
class LWE_amort(LWE):
    """
    Constructs an LWE enviroment that supports multibit encryption.
    
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
    l : int
        plaintext size for amortized enc/dec
    """
    def __init__(self, n=512, q=None, m=None, x=None, l=10):
        self.n, self.q, self.m, self.x, self.l = n, q, m, x, l
        if q==None:
            self.q = random_prime((2*self.n**2), True, (self.n**2))
        if m==None:
            self.m = ((self.n+1)*self.q.log(prec=100)).integer_part()
        if x==None:
            alpha = (1/(sqrt(self.n)*log(self.n)**2))
            self.x = DiscreteGaussianDistributionIntegerSampler(alpha/sqrt(2*pi))
        
        self.VS = GF(self.q)**self.n #vector space, dimension n, modulus q
        self._s = matrix([self.VS.random_element() for i in range(self.l)]) #secret key
        self._pk = self.__genPublicKey() #public key
        
    def __genPublicKey(self):
        a = matrix([self.VS.random_element() for i in range(self.m)]).T
        x = matrix(GF(self.q), (vector([self.x() for i in range(self.l)]) for i in range(self.m)))
        p = (self._s*a)+x.T
        return publicKey_amort(a, p.T, self.q)
    
        
    def enc(self, bitstring, apk):
        """
        Encrypts a bit-string using the given (amortized) key
        
        Parameters
        ----------
        bitstring : plaintext string to encrypt
        apk : amortized public key to encrypt using
        
        Returns
        -------
        cipherText
            object containing vectors a, b, which represents ciphertext of the bitstring)
        """
        for bit in bitstring:
            if bit not in ["1", "0"]:
                raise ValueError("Not a single bit value")
        if len(bitstring) != apk.getL():
            raise ValueError("bitstring incorrect size")
        
        q = apk.getModulus()
        v = vector(GF(q), [int(i) for i in bitstring])
        
        subset = Subsets(apk.getSampleNo()-1).random_element()
        a, b = 0, 0
        for i in subset:
            a += apk.getA(i)
            b += apk.getB(i)
        b += v*math.floor(q/2)
        return cipherText(a%q, b%q)
    
    def dec(self, a):
        """
        Decrypts a cipherText using this instance' secret key
        
        Parameters
        ----------
        a : ciphertext pair to decrypt
        
        Returns
        -------
        string
            decrypted bit-string
            
            
        testval = lift(pair.b-pair.a.inner_product(self._s))
        compval = math.floor(self.q/2)
        
        if (min(0, compval, key = lambda x: abs(x-testval))==0): return 0
        return 1
        """
        d = a.b - self._s*a.a
        gen = lambda i: min(0, math.floor(self.q/2), key = lambda x: x-d[i]==0)
        v = vector([1 if gen(i)==0 else 0 for i in range(0, self.l)])
        return v
    
    def getL(self): return self._l
        
def createLWE(n=512, mb=False, q=None, m=None, x=None, l=10):
    """
    Facade for creating an LWE object
    
    Creates either a single bit or amortized LWE instnace
    
    Parameters
    ----------
    n : int
        security parameter which defines dimension, defaults to 512
    mb : boolean
        if True creates an amortized LWE object, else creates singlebit
    q : int
        modulus, defaults to a random prime in the range of n^2 to 2n^2
    m : int
        desired number of samples for the public key, defaults to (n+1)log(q)
    x : callable object
        error distribution, defaults to a discrete gaussian with standard deviation 1/sqrt(n)log^2(n)
    l : int
        plaintext size for amortized enc/dec (disregarded if single bit)
        
    Returns
    -------
    LWE object
        and LWE object with function enc, dec and getPublicKey functions. See classes LWE and LWE_amort for details.
    
    """
    if mb:
        return LWE_amort(n, q, m, x, l)
    else: return LWE(n, q, m, x)


# Unit Tests
# --------------
# 
# Unit tests for module, including testing helper classes and full LWE implementation, executed when running the below cell (or 
# running the notebook file directly as a python/sage file)

# In[ ]:


class TestHelpers(unittest.TestCase):
    
    def test_publicKey(self): # generate some random matrix and test get functions work as expected
        m, n = (randint(1, 100) for x in range(2))
        q = random_prime(2*n**2, n**2) 
        A = random_matrix(GF(q), m, n-1)
        B = random_matrix(GF(q), m, 1)
        
        key = publicKey(block_matrix(1, 2, [A, B]), q)
        
        for i in range(0, m-1):
            self.assertEqual(A.row(i), key.getA(i))
            self.assertEqual(B[i, 0], key.getB(i))
        self.assertEqual(q, key.getModulus())

    def test_publicKey_adv(self): # generate some random matrix and test get functions work as expected
        m, n, l = (randint(1, 100) for x in range(3))
        q = random_prime(2*n**2, n**2) 
        A = random_matrix(GF(q), m, n)
        B = random_matrix(GF(q), m, l)
        
        key = publicKey_amort(A, B, q)
        
        for i in range(0, n-1):
            self.assertEqual(A.T.row(i), key.getA(i))
        for i in range(0, m-1):
            self.assertEqual(B.row(i), key.getB(i))
        self.assertEqual(q, key.getModulus())

class TestLWE(unittest.TestCase):
    
    def test_LWE_sampling(self): #ie private methods
        n = 20
        mod = random_prime(2*n**2, n**2) 
        test = createLWE(n, q=mod)
        pk = test.getPublicKey()
        
        # list of booleans where each value is true iff entry in public key i,j is less than modulus
        testpk = [lift(pk.getA(i)[j]) < mod and lift(pk.getB(i)) < mod for i in range(0, pk.getSampleNo()) for j in range(0, n)]
        
        self.assertTrue(all(testpk))

        
    def test_LWE(self): #ie tests encryption and decryption pairs equal for a large sample
        
        alice = createLWE(n=80)
        bob = createLWE(n=100)

        tests = 10

        # test alice enc, bob dec
        success = True
        pk = bob.getPublicKey()
        for i in range (0, tests):
            message = randint(0, 1)
            cipher = alice.enc(message, pk)
            plain = bob.dec(cipher)
            if message != plain: success = False   
        self.assertTrue(success)
        
        # test bob enc, alice dec
        success = True
        pk = alice.getPublicKey()
        for i in range (0, tests):
            message = randint(0, 1)
            cipher = bob.enc(message, pk)
            plain = alice.dec(cipher)
            if message != plain: success = False
        self.assertTrue(success)
        
    def test_LWE_amort(self): # test string based methods of LWE
        
        alice = createLWE(80, True)
        bob = createLWE(100, True)
        
        message = "0110110011"
        cipher = alice.enc(message, bob.getPublicKey())
        plain = bob.dec(cipher)
        self.assertEqual([int(i) for i in message], list(plain))
        
        message = "1010111100"
        cipher = bob.enc(message, alice.getPublicKey())
        plain = alice.dec(cipher)
        self.assertEqual([int(i) for i in message], list(plain))

if __name__ == '__main__':
    unittest.main(argv=['-v'], verbosity=2, exit=False)


# In[ ]:



