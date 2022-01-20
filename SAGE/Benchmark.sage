import import_ipynb

import LWE.standard.LWE_PKE as LWE_PKE
import LWE.ring.FHE_RLWE as FHE_RLWE


print("Benchmarking Standard LWE PKE at bit security 128, message size 32\n"\
      "******************************************************************")
lwe = LWE_PKE.createLWE(n=752, mb=True, q=random_prime(2^16-1, True, 2^15), l=32)
print("\nPublic Key Generation time:")
print(timeit('lwe = LWE_PKE.createLWE(n=752, mb=True, q=random_prime( 2^16-1, True, 2^15), l=32)'))

apk = lwe.getPublicKey()

print("\nEncryption time:")
print(timeit('binary = \'\'.join(map(lambda x: str(x), [randint(0, 1) for i in range(0, 32)]))\nlwe.encrypt(binary, apk)'))

binary = ''.join(map(lambda x: str(x), [randint(0, 1) for i in range(0, 32)]))
cipher = lwe.encrypt(binary, apk)

print("\nDecryption time:")
print(timeit('lwe.decrypt(cipher)'))

print("\n\nBenchmarking Ring LWE PKE at bit security 128, message size 32\n"\
      "**************************************************************")
lwe = FHE_RLWE.createFHE(sec_lambda=128, n=1024)
print("\nPublic Key Generation time:")
print(timeit('lwe = FHE_RLWE.createFHE(sec_lambda=128, n=1024)'))

apk = lwe.getPublicKey()

print("\nEncryption time:")
print(timeit('binary = [randint(0, 1) for i in range(0, 32)]\nlwe.encrypt(binary, apk)'))

binary = [randint(0, 1) for i in range(0, 32)]
cipher = lwe.encrypt(binary, apk)

print("\nDecryption time:")
print(timeit('lwe.decrypt(cipher)'))