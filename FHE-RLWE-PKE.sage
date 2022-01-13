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

# In[1]:


import unittest
import random


# FHE Class
# ---------

# In[2]:


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
    def __init__(self, sec_lambda=256):
        R.<x> = PolynomialRing(ZZ)
        self.R = QuotientRing(R, R.ideal(x^sec_lambda + 1))
        
        self._sk = self.SecretKeyGen(self.R)
        
        
    def SecretKeyGen(self, R):
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
        r_sam = R.random_element()
        monic = R.lift(r_sam)%2
        return R(monic)


# In[ ]:





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




