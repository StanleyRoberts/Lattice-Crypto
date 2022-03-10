import sage.all
import unittest
from LWE_PKE import *
from sage.misc.prandom import randint
from sage.matrix.special import random_matrix, block_matrix

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
        
        testpka = [lift(pk.getA(i)[j]) < mod for i in range(0, pk.getSampleNo()) for j in range(0, n)]
        testpkb = [lift(pk.getB(i))[j] < mod for i in range(0, pk.getSampleNo()) for j in range(0, len(pk.getB(i)))]
        
        self.assertTrue(all(testpka))
        self.assertTrue(all(testpkb))

        
    def test_LWE(self): #ie tests encryption and decryption pairs equal for a large sample
        
        alice = createLWE(80, False)
        bob = createLWE(100, False)

        tests = 10

        # test alice enc, bob dec
        success = True
        pk = bob.getPublicKey()
        for i in range (0, tests):
            message = randint(0, 1)
            cipher = alice.encrypt(str(message), pk)
            plain = bob.decrypt(cipher)
            if message != plain: success = False   
        self.assertTrue(success)
        
        # test bob enc, alice dec
        success = True
        pk = alice.getPublicKey()
        for i in range (0, tests):
            message = randint(0, 1)
            cipher = bob.encrypt(str(message), pk)
            plain = alice.decrypt(cipher)
            if message != plain: success = False
        self.assertTrue(success)
        
    def test_LWE_amort(self): # test string based methods of LWE
        
        alice = createLWE(80)
        bob = createLWE(100)
        
        message = "0110110011"
        cipher = alice.encrypt(message, bob.getPublicKey())
        plain = bob.decrypt(cipher)
        self.assertEqual([int(i) for i in message], list(plain))
        
        message = "1010111100"
        cipher = bob.encrypt(message, alice.getPublicKey())
        plain = alice.decrypt(cipher)
        self.assertEqual([int(i) for i in message], list(plain))

if __name__ == '__main__':
    unittest.main(argv=['-v'], verbosity=2, exit=False)