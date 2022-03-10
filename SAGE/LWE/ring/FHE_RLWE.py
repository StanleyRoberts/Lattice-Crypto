import sage.all
import random
from math import floor as int_floor
from sage.stats.distributions.discrete_gaussian_polynomial import DiscreteGaussianDistributionPolynomialSampler
from sage.stats.distributions.discrete_gaussian_integer import DiscreteGaussianDistributionIntegerSampler
from sage.symbolic.constants import pi
from sage.misc.functional import lift
from sage.misc.prandom import randint, choice
from sage.rings.polynomial.polynomial_ring_constructor import PolynomialRing
from sage.rings.finite_rings.integer_mod_ring import Zmod
from sage.rings.quotient_ring import QuotientRing
from sage.rings.integer_ring import ZZ
from sage.rings.rational_field import QQ
from sage.functions.log import log
from sage.functions.other import sqrt, ceil, floor
from sage.calculus.var import var
from abc import ABCMeta, abstractmethod

"""
Name
----
FHE_RLWE

Description
-----------
This module implements a fully homomorphic public key cryptography system based on Ring-LWE

Contents
--------
publicKey : Public key data type for Fully Homomorphic R-LWE
FHE : object representing an FHE R-LWE system
cipherText : A polynomial representing an R-LWE ciphertext
createFHE : function that returns an FHE object
"""

def param_gen(sec, n):
    '''
    Generates an appropriate log2(q) parameter according to FHE standards such that
    a polynomial coefficient modulus n is generated such that 2^q =< n < 2^(q+1)
    Undefined for unexpected inputs.
    
    Parameters
    ----------
    sec: int
        int in [128, 192, 256] defining the bit security
    n: int
        int in [1024, 2048, 4096, 8192, 16384, 32768] defining the polynomial size
    
    Returns
    -------
    int
        int represennting log(q) to generate polynomial coefficient modulus
    '''
    table = [[29, 21, 16], [56, 39, 31], [111, 77, 60], [220, 154, 120], [440, 307, 239], [880, 612, 478]]
    lq = 0 if sec==128 else 1 if sec==192 else 2
    m = log(n,2)-10
    return table[m][lq]

def poly(l):
    '''
    Given a list l composed of elements [l0, l1, l2,...,li], returns the polynomial 'form' of list as:
    l0 * x^0 + l1 *x^1 + ... + li + x^i
        
    Parameters
    ----------
    l : list
        list of integers to generate polynomial using    
        
    Returns
    -------
    SageMath polynomial
        a polynomial composed from given list
    '''
    polys = 0
    x = var('x')
    for i in range(0, len(l)):
        polys += l[i]*x**(i)
    return polys
    
def rering(p, n):
    '''
    Casts an element of a specific ring (with coefficient and polynomial modulus)
    into a generic rational polynomial ring mod x^n + 1
    
    Parameters
    ----------
    p : SageMath polynomial
        polynomial in ring to remove coefficient modulus
    n : int
        polynomial exponent for polynomial modulus such that modulus = x^n + 1
        
    Returns
    -------
    SageMath polynomial
        a polynomial raised out of the coefficient modulus ring
    '''
    R = PolynomialRing(QQ, names=('x',)); (x,) = R._first_ngens(1)
    Rzx = QuotientRing(R, R.ideal(x**n + 1))
    return Rzx(p.lift())

def decomp(i, t):
    '''
    Decomposes an integer i into base t
    
    Parameters
    ----------
    i : int
        integer to decompose
    t : int
        base to decompose using
        
    Returns
    -------
    list
        integer list of decomposed integer
    '''
    if i<t: return [i]
    else: return [i%t] + decomp(i//t, t)
    
class publicKey():
    """
    A public key object
    
    Parameters
    ----------
    key : tuple
        the public key pair of polynomials assocaited with the secret key
    ring : SageMath Ring
        the SageMath ring the polynomials are in
    n : int
        the polynomial power
    t : int
        the plaintext modulus
    q : int
        the polynomial coefficient modulus
    rlk : tuple
        tuple representing the relinearisation key and base T
    depth : int
        multiplication depth of the associated FHE instance
    """
    def __init__(self, key, ring, n, t, q, rlk, depth, chi):
        self.key, self.ring, self.n, self.t, self.q, self.rlk, self.depth, self.chi = key, ring, n, t, q, rlk, depth, chi
        
    def __str__(self): return self.key.__str__() + " ring: " + self.ring.__str__()
    
class ciphertext():
    """
    Ring-LWE FHE ciphertext object with built in multiplication, addition 
    and tracking of mulltiplication depth
    """
    def __init__(self, pair, pk, depth=None):
        self.pair, self.pk, self.depth = pair, pk, depth
        if not depth:
            self.depth = pk.depth
    
    def __add__(self, other):
        c1, c2 = self.pair, other.pair
        depth = max(c1, c2)
        return ciphertext((c1[0]+c2[0], c1[1]+c2[1]), self.pk, depth)
    
    def __radd__(self, other): return self.__add__(other)
        
    def __mul__(self, other):
        if (self.pk!=other.pk): raise AttributeError("ciphertexts belong to different instances")
        depth = min(self.depth, other.depth)-1
        if depth < 1:
            raise ArithmeticError("multiplication depth exceeded")
        pk = self.pk
        rlk, T = pk.rlk[0], pk.rlk[1]
        ct1 = rering(self.pair[0], pk.n), rering(self.pair[1], pk.n)
        ct2 = rering(other.pair[0], pk.n), rering(other.pair[1], pk.n)
        l = int_floor(log(pk.q, T))
        
        c0 = pk.ring(poly([round(i*(pk.t/pk.q)) for i in (ct1[0]*ct2[0]).lift().coefficients(sparse=False)]))
        c1 = pk.ring(poly([round(i*(pk.t/pk.q)) for i in (ct1[0]*ct2[1]+ct1[1]*ct2[0]).lift().coefficients(sparse=False)]))
        c2 = pk.ring(poly([round(i*(pk.t/pk.q)) for i in (ct1[1]*ct2[1]).lift().coefficients(sparse=False)]))
        
        c20 = [decomp(x.lift(), T) for x in c2.lift().coefficients(sparse=False)][::-1]
        for i in c20:
            if len(i)<l: i.append(0)

        polys = [pk.ring(poly([ls[i] for ls in c20][::-1])) for i in range(0, l)]

        nct0 = c0 + sum([rlk[i][0]*polys[i] for i in range(0, l)])
        nct1 = c1 + sum([rlk[i][1]*polys[i] for i in range(0, l)])

        return ciphertext((nct0, nct1), self.pk, depth)
    def __str__(self):
        return self.pair[0].__str__() + self.pair[1].__str__() + "Depth: " +self.depth.__str__()
    
    def getPK(self): return self.pk
    
    def getRemainingDepth(self): return self.depth
    
    def __getitem__(self, key):
        if key<2:
            return self.pair[key]
        else:
            raise IndexError("index must be natural <2")
            
class FHE_raw():
    """
    Constructs a (Leveled) Fully Homomorphic Encryption Enviroment
    
    Constructs a new encryption environment who can be used as
    an LWE_PKE object but also provides addition and multiplication
    on encrypted ciphertexts and has security based on R-LWE
    
    This class operates on pure ciphertexts who are simply polynomial pairs
    
    Parameters
    ----------
    sec_lambda : int
        security parameter which defines dimension, defaults to 512
    n : int
        power of 2, larger n decreases efficiency but increases circuit depth and polynomial length
    error_dist : callable function
        generates errors (small polynomials) key generation
    t : int
        plaintext coefficient modulus
    q : int
        ciphertext coefficient modulus
    """
    def __init__(self, sec_lambda=128, n=4096, t=20, logq=None, error_dist=None):
        if not logq:
            logq = param_gen(sec_lambda, n)
        q =  randint(2**logq, 2**(logq+1))
        self.q, self.t, self.n = q, t, n
        
        #R.<x> = PolynomialRing(Zmod(self.q))
        R = PolynomialRing(Zmod(self.q), names=('x',)); (x,) = R._first_ngens(1)
        self.R = QuotientRing(R, R.ideal(x**n + 1)) #univariate polynomial ring with f(x)=x^n+1 
        
        self.chi = error_dist
        if not error_dist:
            sigma=8/sqrt(2*pi)
            self.chi = DiscreteGaussianDistributionPolynomialSampler(self.R, n, sigma)
        
        
        self._sk = None
        self._pk = None
        
    def getPublicKey(self):
        if self._checkForPK():
            self._sk = self._SecretKeyGen()
            self._pk = self._PublicKeyGen(self._sk)
        return self._pk
    
    def getCircuitDepth(self):
        return floor((-(2*log(2) + log(9.2) + log(8/sqrt(2*pi)) - log(self.q) + log(self.n + 5/4)\
                 - log(self.t))/(log(self.n + 5/4) + log(self.n) + log(self.t))).n())
    
    def _checkForPK(self):
        return self._sk == None
    
    def _AOPishGen(self, length, mod):
        # AOPish meaning an all-one-polynomial who is also allowed negative or zero coefficients
        AOPish = []
        for i in range(0, length):
            AOPish.append(choice([1, 0, mod-1]))
        return poly(AOPish)
        
    def _SecretKeyGen(self):
        return self.R(self._AOPishGen(self.n, self.q))
    
    def _PublicKeyGen(self, sk):
        a = self.R.random_element()
        e = self.chi()
        key = (self.R(-a*sk+e), a)
        return publicKey(key, self.R, self.n, self.t, self.q, self.rlk1(), self.getCircuitDepth(), self.chi)
    
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
        if self._checkForPK():
            raise AttributeError("secret (and public) key does not exist")
        p = c[0]+c[1]*self._sk
        p = p.lift().coefficients(sparse=False)
        nl = [round(QQ(self.t)*QQ(i)/QQ(self.q)) for i in p]
        return list(map(lambda x: x%self.t, nl))[::-1]
    
    def rlk1(self):
        """
        Generates a Version 1 relinearisation key
        
        Returns
        -------
        tuple
            a tuple consisting of the relinearisation pair and the base
        """
        self.getPublicKey()
        T = ceil(sqrt(self.q)) #essentially arbritrary
        rlk = []
        for i in range(0, int(log(self.q, T).n())):
            # int(log(q, T).n()) works better than floor(log(q, T)) for large q which may appear in boostrapping FHE systems
            a = self.R.random_element()
            rlk.append([-a*self._sk+self.chi() + T**i * self._sk * self._sk, a])
        return (rlk, T)
    
    def encrypt(self, m, pk):
        """
        Encrypts a plaintext list using public key pk
        
        Parameters
        ----------
        pk : public key to encrypt using
        
        m : plaintext list to encrypt
        
        Returns
        -------
        tuple
            a pair of two polynomials who are a BFV ciphertext
        """
        m = pk.ring(poly(m[::-1]))
        p0, p1 = pk.key
        
        ZZx = PolynomialRing(ZZ, 'x')
        u = pk.ring(self._AOPishGen(pk.n, pk.q))
        e1,e2 = pk.chi(), pk.chi()
        
        a = p0*u + e1 + floor(pk.q/pk.t)*m
        b = p1*u + e2
        return a, b    
    
    def add(self, c1, c2):
        """
        Adds to ciphertext pairs together
        
        Parameters
        ----------
        c1 : first ciphertext pair to add
        c2 : second ciphertext pair to add
        
        Returns
        -------
        tuple
            a pair of two polynomials representing a ciphertext
        """
        return (c1[0]+c2[0], c1[1]+c2[1])
    
    def mul1(self, ct1, ct2, key):
        """
        Multiplies two ciphertext together (and relinearises them based on the key)
        using Version 1 relinearisation
        
        Parameters
        ----------
        ct1 : first ciphertext pair to multiply
        ct2 : second ciphertext pair to multiply
        key : key to relinearise using
        
        Returns
        -------
        tuple
            a pair of two polynomials representing a ciphertext
        """
        # need to raise polynomials out of both quotient rings then return them to ring mod x^n+1
        pk = key.pk
        rlk, T = key.rlk[0], key.rlk[1]
        ct1 = rering(ct1[0], pk.n), rering(ct1[1], pk.n)
        ct2 = rering(ct2[0], pk.n), rering(ct2[1], pk.n)
        l = int_floor(log(pk.q, T))
        
        c0 = pk.ring(poly([round(i*(pk.t/pk.q)) for i in (ct1[0]*ct2[0]).lift().coefficients(sparse=False)]))
        c1 = pk.ring(poly([round(i*(pk.t/pk.q)) for i in (ct1[0]*ct2[1]+ct1[1]*ct2[0]).lift().coefficients(sparse=False)]))
        c2 = pk.ring(poly([round(i*(pk.t/pk.q)) for i in (ct1[1]*ct2[1]).lift().coefficients(sparse=False)]))
        
        c20 = [decomp(x.lift(), T) for x in c2.lift().coefficients(sparse=False)][::-1]
        for i in c20:
            if len(i)<l: i.append(0)

        polys = [pk.ring(poly([ls[i] for ls in c20][::-1])) for i in range(0, l)]

        nct0 = c0 + sum([rlk[i][0]*polys[i] for i in range(0, l)])
        nct1 = c1 + sum([rlk[i][1]*polys[i] for i in range(0, l)])

        return nct0, nct1

    
class FHE_raw_b(FHE_raw):
    '''
    Implements a true fully homomorphic encryption enviroment using bootstrapping
    This class only implements parameter selection and bootstrapping should be done externally.
    '''
    __metaclass__ = ABCMeta
    def __init__(self, sec_lambda, n_scale=1):
        log_delta = 1.8/(sec_lambda+110)
        Hf = 1 #for simplicity assume parameterized family x^n+1
        self.t = 2 #plaintext space
        h = 63 #hamming weight
        alpha, beta = 3.8, 9.2 #with e=2^-64
        d=2**10 #set d=2^k (and q=2^n)
        L_min = ceil(log(self.t * 2 * (Hf*h + 1) + 0.5, 2))
        

        top = log(4*alpha*beta*self.t**(L_min-1),2) + (2*L_min+1)*log(d,2)
        bot = 2*sqrt(d*log_delta)
        self.n= ceil((top/bot)**2)*2**n_scale
        self.q = randint(2**self.n, 2**(self.n+1)) #coefficient modulus
        
        #R.<x> = PolynomialRing(Zmod(self.q))
        R = PolynomialRing(Zmod(self.q), names=('x',)); (x,) = R._first_ngens(1)
        self.R = QuotientRing(R, R.ideal(x**d + 1)) #univariate polynomial ring with f(x)=x^n+1 
        
        sigma=ceil((alpha*self.q)/2**(2*sqrt(d*log_delta*self.n)))
        self.chi = DiscreteGaussianDistributionPolynomialSampler(R, d, sigma)
        
        self._sk = None
        self._pk = None
    
    @abstractmethod
    def bootstrap(self): pass
    
class FHE(FHE_raw):
    """
    A wrapper for FHE_raw, has a larger memory overhead but
    provides useful functionality like multiplication depth tracking
    
    Using FHE_raw may be preferred if you wish to use custom parameters or
    require smaller ciphertext sizes however note that the raw version
    provides no type-checking and multiplication depth must be manually tracked
    """
    def encrypt(self, m, pk):
        """
        Encrypts a plaintext list using public key pk
        
        Parameters
        ----------
        pk : public key to encrypt using
        
        m : plaintext list to encrypt
        
        Returns
        -------
        tuple
            a pair consistenting of the encrypted message and the public key
        """
        return ciphertext(FHE_raw.encrypt(self, m, pk), pk)
    
    def add(self, c1, c2):
        """
        Adds two cipher texts
        
        Parameters
        ----------
        c1, c2 : tuple
            tuples each representing a ciphertext
        
        Returns
        -------
        tuple
            a new ciphertext object
        """
        return c1+c2
    
    def mul1(self, c1, c2, key):
        """
        Multiplies two cipher texts
        
        Parameters
        ----------
        c1, c2 : tuple
            tuples each representing a ciphertext
        
        Returns
        -------
        tuple
            a new ciphertext object
        """
        return c1*c2
    
    def decrypt(self, c):
        """
        Decrypts a ciphertext according to secret key
        
        Parameters
        ----------
        c : ciphertext
            ciphertext to decrypt
        
        Returns
        -------
        list
            a list representation of the decryption
        """
        return FHE_raw.decrypt(self, c.pair)
    
def createFHE(pt_coeff=20, security=128, n=4096):
    """
    Creates a very simple FHE enviroment. Most parameters are predefined
    and memory overhead is high to allow easier manipulations of encrypted
    data without worrying about multiplication depths and maintaining public
    keys/ciphertext origins.
    Public/secret keys and other properties are only generated when neccesary
    allowing efficient use for parties who only encrypt or operate on data.
    
    Should you wish to use a purer form of BFV see FHE_raw
    Should you wish to use a bootstrappable BFV see FHE_raw_b 
        
    Parameters
    ----------
    pt_coeff : plaintext modulus
        the modulus to plaintext polynomial coefficients.
        eg plaintext 2x^2 + 4x + 9 with pt_coeff = 4 becomes 2x^2 + 1
    
    security : int
        bit security of the scheme, defined for 128, 192 and 256
        
    n : int
        defines the polynomial degree for plaintexts and ciphertexts.
        increasing results in longer computation but deeper multiplication depths

    Returns
    -------
    FHE
        an FHE object supporting encryption, addition, multiplication and decryption (if full)
    """
    try:
        logq = param_gen(security, n)
    except IndexError:
        raise TypeError("n does not belong to recommended values."\
                        " use the raw classes if you want to define custom parameters")
    return FHE(security, n, pt_coeff, logq)