from FHE_RLWE import *
import sage.all
import unittest
from sage.symbolic.expression import Expression

class testFHE(unittest.TestCase):
    def setUp(self):
        nval = 2**randint(8, 10)
        self.alice = FHE(n=nval)
        while (self.alice.getCircuitDepth() < 1):
            nval = 2**randint(8, 10)
            self.alice = FHE(n=nval)
        nval = 2**randint(10, 12)
        self.bob = FHE(n=nval)
            
        self.pk = self.alice.getPublicKey()
    
    def test_secretKey(self):
        key = self.alice._sk.lift()
        mod = self.pk.q
        coef = key.coefficients(sparse=False)
        for i in coef:
            if abs(i.lift()) not in [1, mod-1, 0]:
                self.fail("secret key coefficients not in {-1, 0, 1}")
        self.assertLessEqual(key.degree(), self.pk.n)
        
    def test_enc_dec(self):
        plain_length = self.pk.n
        plain_mod = self.pk.t
        message = [randint(0, plain_mod-1) for i in range(0, plain_length)]
        cipher = self.bob.encrypt(message, self.pk)
        plain = self.alice.decrypt(cipher)
        self.assertEqual(message, plain)
        
    def test_fhe_mul(self):
        message1 = [randint(0, self.pk.t-1) for i in range(0, self.pk.n)]
        message2 = [randint(0, self.pk.t-1) for i in range(0, self.pk.n)]

        cipher1 = self.bob.encrypt(message1, self.pk)
        cipher2 = self.bob.encrypt(message2, self.pk)
        plain = self.alice.decrypt(cipher1*cipher2)

        ring = PolynomialRing(Zmod(self.pk.t), 'x')
        ring = QuotientRing(ring, ring.ideal(x**self.pk.n + 1))
        message = (ring(poly(message1[::-1]))*ring(poly(message2[::-1]))).lift().coefficients(sparse=False)[::-1]

        self.assertEqual(message, plain)

    def test_dhe_add(self):
        message1 = [randint(0, self.pk.t-1) for i in range(0, self.pk.n)]
        message2 = [randint(0, self.pk.t-1) for i in range(0, self.pk.n)]

        cipher1 = self.bob.encrypt(message1, self.pk)
        cipher2 = self.bob.encrypt(message2, self.pk)
        plain = self.alice.decrypt(cipher1+cipher2)

        ring = PolynomialRing(Zmod(self.pk.t), 'x')
        x = var('x')
        ring = QuotientRing(ring, ring.ideal(x**self.pk.n + 1))
        message = (ring(poly(message1[::-1]))+ring(poly(message2[::-1]))).lift().coefficients(sparse=False)[::-1]

        self.assertEqual(message, plain)
        
    def test_err(self):
        message = [randint(0, self.pk.t-1) for i in range(0, self.pk.n)]
        bpk = self.bob.getPublicKey()
        cipher1 = self.alice.encrypt(message, self.pk)
        cipher2 = self.alice.encrypt(message, bpk)
        
        # test we cannot multiply ciphers from different instances
        with self.assertRaises(AttributeError):
            cipher1*cipher2
            
        # test we get error when decrypting an impossible cipher
        # ie, not secret key generated so no valid cipher exists
        with self.assertRaises(AttributeError):
            new = FHE()
            new.decrypt(cipher1)
            
        # test we get depth error exactly when expected
        for i in range(0, self.alice.getCircuitDepth()-1):
            cipher1 *= cipher1
        with self.assertRaises(ArithmeticError):
            cipher1 *= cipher1
            

if __name__ == '__main__':
    unittest.main(argv=['-v'], verbosity=2, exit=False)