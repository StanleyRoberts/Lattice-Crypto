import sage.all

import copy
import math
import random

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
from sage.symbolic.expression import Expression

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
createLWE : function that returns an LWE object
"""

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
        self._sk = self.VS.random_element() #secret key
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
        b = self._sk.inner_product(a) + er
        return vector(Integers(self.q), list(a)+[b.lift()])

    def __genPublicKey(self):
        # generates a public key by combining m samples (from sampler) into a matrix form
        
        vector_list = [self.__LWEsample() for x in range(self.m)]
        return publicKey(matrix(vector_list), self.q)

    def encrypt(self, bit, key):
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
    
    def decrypt(self, pair):
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
        testval = lift(pair.b-pair.a.inner_product(self._sk))
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
            self.x = DiscreteGaussianDistributionIntegerSampler(alpha) #/sqrt(2*pi))
        
        self.VS = GF(self.q)**self.n #vector space, dimension n, modulus q
        self._sk = matrix([self.VS.random_element() for i in range(self.l)]) #secret key
        self._pk = self.__genPublicKey() #public key
        
    def __genPublicKey(self):
        a = matrix([self.VS.random_element() for i in range(self.m)]).T
        x = matrix(GF(self.q), (vector([self.x() for i in range(self.l)]) for i in range(self.m)))
        p = (self._sk*a)+x.T
        return publicKey_amort(a, p.T, self.q)
    
        
    def encrypt(self, bitstring, apk):
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
                raise ValueError("Not binary string")
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
    
    def decrypt(self, a):
        """
        Decrypts a cipherText using this instance' secret key
        
        Parameters
        ----------
        a : ciphertext pair to decrypt
        
        Returns
        -------
        string
            decrypted bit-string
            
            
        testval = lift(pair.b-pair.a.inner_product(self._sk))
        compval = math.floor(self.q/2)
        
        if (min(0, compval, key = lambda x: abs(x-testval))==0): return 0
        return 1
        """
        d = a.b - self._sk*a.a
        gen = lambda i: min(0, math.floor(self.q/2), key = lambda x: x-d[i]==0)
        v = vector([1 if gen(i)==0 else 0 for i in range(0, self.l)])
        return v
    
    def getL(self): return self._l
        
def createLWE(n=512, mb=True, q=None, m=None, x=None, l=10):
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