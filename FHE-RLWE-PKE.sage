#!/usr/bin/env python
# coding: utf-8

# Fully Homomorphic Encryption
# ==========================
# 
# This is a Fully Homomorphic Encryption system whose security is based on Ring-LWE.
# This system is an implementation of the Fan-Vercauteren FHE mechanism using Gentry's bootstrapping
# 
# &nbsp;
# &nbsp;
# &nbsp;
# 
# Imports
# -----------

# In[6]:


import unittest
import random
from sage.stats.distributions.discrete_gaussian_polynomial import DiscreteGaussianDistributionPolynomialSampler
from sage.stats.distributions.discrete_gaussian_integer import DiscreteGaussianDistributionIntegerSampler


# Helpers
# -----------

# In[7]:


def param_gen(sec, n):
    '''
    Generates appropriate parameters according to FHE standards
    sec = [128, 192, 256]
    n = [1024, 2048, 4096, 8192, 16384, 32768]
    '''
    table = [[29, 21, 16], [56, 39, 31], [111, 77, 60], [220, 154, 120], [440, 307, 239], [880, 612, 478]]
    lq = 0 if sec==128 else 1 if sec==192 else 2
    m = log(n,2)-10
    return table[m][lq]

def poly(l):
    '''
    Given a list l composed of elements [l0, l1, l2,...,li], returns the polynomial 'form' of list as:
    l0 * x^i + l1 *x^i-1 + ... + li + x^0
    '''
    poly = 0
    for i in range(0, len(l)):
        poly += l[i]*x^(len(l)-i-1)
    return poly
    


# FHE Class
# ---------
# For both security and simplicity reasons we operate on the standard polynomial Ring ZZx/f(x) where f(x) = x^n + 1

# In[31]:


class FHE():
    """
    Constructs a (Leveled) Fully Homomorphic Encryption Enviroment
    
    Constructs a new encryption environment who can be used as
    an LWE_PKE object but also provides addition and multiplication
    on encrypted ciphertexts and has security based on R-LWE
    
    Parameters
    ----------
    sec_lambda : int
        security parameter which defines dimension, defaults to 512
    n : int
        power of 2, larger n decreases efficiency but increases circuit depth
    """
    def __init__(self, sec_lambda=128, n=4096, error_dist=None, t=2):
        lq = param_gen(sec_lambda, n)
        self.q, self.t, self.n = randint(2^lq, 2^(lq+1)), t, n
        self.delta = floor(self.q/self.t)
        
        R.<x> = PolynomialRing(Zmod(self.q))
        self.R = QuotientRing(R, R.ideal(x^n + 1)) #univariate polynomial ring with f(x)=x^n+1 
        
        self.chi = error_dist
        if not error_dist:
            sigma=8/sqrt(2*pi)
            self.chi = DiscreteGaussianDistributionPolynomialSampler(self.R, n, sigma)
        
        
        self._sk = self._SecretKeyGen()
        self._pk = self._PublicKeyGen(self._sk)
        
    def getPublicKey(self): return self._pk
    
    def getCoeffMod(self): return self.q
    
    def getPlaintextSpace(self): return (self.t, getCoeffMod())
    
    def getCircuitDepth(self):
        return floor((-(2*log(2) + log(9.2) + log(8/sqrt(2*pi)) - log(self.q) + log(self.n + 5/4)                 - log(self.t))/(log(self.n + 5/4) + log(self.n) + log(self.t))).n())
        
    def _SecretKeyGen(self):
        """
        Generates a (monic polynomial) secret key
        
        Parameters
        ----------
        R : Ring to generate monic key from
        
        Returns
        -------
        secret_key
            a monic polynomial in R
        """
        monic = []
        for i in range(0, self.n):
            monic.append(choice([1, 0, self.q]))
        return self.R(poly(monic))
    
    def _PublicKeyGen(self, sk):
        """
        Generates a public key pair of polynomials
        
        Parameters
        ----------
        sk : secret key to generate public key from
        
        Returns
        -------
        public_key
            a pair of two polynomials in R (a, b) where b is some random polynomial
            and a is: b modified by the secret key and adjusted by some error
        """
        a = self.R.random_element()
        e = self.chi()
        return (self.R(-a*sk+e), a)
    
    def encrypt(self, pk, m):
        """
        Encrypts a plaintext list using public key pk
        
        Parameters
        ----------
        pk : public key to encrypt using
        
        m : plaintext list to encrypt
        
        Returns
        -------
        ciphertext pair
            a pair of two polynomials who are a BFV ciphertext
        """
        m = self.R(poly(m))
        p0, p1 = pk
        
        ZZx = PolynomialRing(ZZ, 'x')
        u = self._SecretKeyGen()
        e1,e2 = self.chi(), self.chi()
        
        a = p0*u + e1 + self.delta*m
        b = p1*u + e2
        return a, b
    
    def decrypt(self, c):
        """
        Decrypt a ciphertext pair using instances secret key
        
        Parameters
        ----------
        c : ciphertext pair to decrypt
        
        Returns
        -------
        list
            plaintext list
        """
        p = c[0]+c[1]*self._sk
        p = p.lift().coefficients(sparse=False)
        nl = []
        for i in p:
            nl.append(round(QQ(self.t)*QQ(i)/QQ(self.q)))
        return list(map(lambda x: x%self.t, nl))[::-1]
    
class FHE_b(FHE):
    '''
    Implements a true fully homomorphic encryption enviroment using bootstrapping
    This class only implements parameter selection and bootstrapping should be done externally.
    '''
    def __init__(self, sec_lambda, n_scale=1):
        log_delta = 1.8/(sec_lambda+110)
        Hf = 1 #for simplicity assume parameterized family x^n+1
        self.t = 2 #plaintext space
        h = 63 #hamming weight
        alpha, beta = 3.8, 9.2 #with e=2^-64
        d=2^10 #set d=2^k (and q=2^n)
        L_min = ceil(log(self.t * 2 * (Hf*h + 1) + 0.5, 2))
        

        top = log(4*alpha*beta*self.t^(L_min-1),2) + (2*L_min+1)*log(d,2)
        bot = 2*sqrt(d*log_delta)
        self.n= ceil((top/bot)^2)*2^n_scale
        self.q = randint(2^self.n, 2^(self.n+1)) #coefficient modulus
        self.delta = floor(self.q/self.t)
        
        R.<x> = PolynomialRing(Zmod(self.q))
        self.R = QuotientRing(R, R.ideal(x^d + 1)) #univariate polynomial ring with f(x)=x^n+1 
        
        sigma=ceil((alpha*self.q)/2^(2*sqrt(d*log_delta*self.n)))
        self.chi = DiscreteGaussianDistributionPolynomialSampler(R, d, sigma)
        
        
        self._sk = self._SecretKeyGen()
        self._pk = self._PublicKeyGen(self._sk)
        


# In[34]:


fhe = FHE(128)
print(fhe.getCoeffMod())
cipher = fhe.encrypt(fhe.getPublicKey(), [1, 0, 0, 1, 1, 0, 1, 1])
print(cipher[0])
print(cipher[1])
plain = fhe.decrypt(cipher)
print(plain)
depth = fhe.getCircuitDepth()
print(depth)


# Unit Tests
# --------------

# In[ ]:


class testFHE(unittest.TestCase):
    def test_secretKey(self):
        n = randint(1, 512)
        fhe = FHE(n)
        key = fhe._sk.lift()
        coef = key.coefficients(sparse=False)
        for i in coef:
            if abs(i) not in [1, -1, 0]:
                self.fail("non-monic secret key")
        self.assertLessEqual(key.degree(), n)
        
        

if __name__ == '__main__':
    unittest.main(argv=['-v'], verbosity=2, exit=False)


# In[ ]:




