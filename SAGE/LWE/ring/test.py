from FHE_RLWE import *
import unittest

class testFHE(unittest.TestCase):
    def test_secretKey(self):
        nval = 2**randint(8, 12)
        fhe = FHE(n=nval)
        key = fhe._sk.lift()
        coef = key.coefficients(sparse=False)
        for i in coef:
            if abs(i.lift()) not in [1, -1, 0]:
                self.fail("non-monic secret key")
        self.assertLessEqual(key.degree(), nval)
        
        

if __name__ == '__main__':
    unittest.main(argv=['-v'], verbosity=2, exit=False)