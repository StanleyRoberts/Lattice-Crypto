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

# In[15]:


import unittest
import random
from sage.stats.distributions.discrete_gaussian_polynomial import DiscreteGaussianDistributionPolynomialSampler
from sage.stats.distributions.discrete_gaussian_integer import DiscreteGaussianDistributionIntegerSampler


# FHE Class
# ---------

# In[208]:


class FHE():
    """
    Constructs a Fully Homomorphic Encryption Enviroment
    
    Constructs a new encryption environment who can be used as
    an LWE_PKE object but also provides addition and multiplication
    on encrypted ciphertexts and has security based on R-LWE
    
    Parameters
    ----------
    sec_lambda : int
        security parameter which defines dimension, defaults to 512
    """
    def __init__(self, sec_lambda=128):
        log_delta = 1.8/(sec_lambda+110)
        Hf = 1 #for simplicity assume parameterized family x^n+1
        t = 2 #plaintext space
        h = 63 #hamming weight
        alpha, beta = 3.8, 9.2 #with e=2^-64
        d=2^10 #set d=2^k (and q=2^n)
        L_min = ceil(log(t * 2 * (Hf*h + 1) + 0.5, 2))
        

        top = log(4*alpha*beta*t^(L_min-1),2) + (2*L_min+1)*log(d,2)
        bot = 2*sqrt(d*log_delta)
        n=ceil((top/bot)^2)
        self.q = 2^n #coefficient modulus
        
        R.<x> = PolynomialRing(Zmod(self.q))
        self.R = QuotientRing(R, R.ideal(x^d + 1)) #univariate polynomial ring with f(x)=x^n+1 
        
        sigma=ceil((alpha*self.q)/2^(2*sqrt(d*log_delta*n)))      
        self.chi = DiscreteGaussianDistributionPolynomialSampler(R, d, sigma)
        
        self._sk = self.SecretKeyGen()
        self._pk = self.PublicKeyGen(self._sk)
        
    def SecretKeyGen(self):
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
        ZZx = PolynomialRing(ZZ, 'x')
        r_sam = self.R.random_element().lift()
        monic = ZZx(r_sam)%2
        return self.R(monic)
    
    def PublicKeyGen(self, sk):
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


# In[209]:


fhe = FHE(128)


# Unit Tests
# --------------

# In[3]:


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




