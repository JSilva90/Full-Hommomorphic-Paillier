import random
import math
from fractions import gcd

"""
This piece of code implements the traditional paillier hommomorphic cryptosystem.
The main functions are keys generation, encrpytion and decryption.
Futhermore there are 3 hommomophic opeations: two cipher addition, cipher and constant addition
cipher and constant multiplication.
"""

class PrivateKey():
    """
    Object for a private key on paillier's cryptosystem
    """

    def __init__ (self, p, q):
        """
        Construct a new PrivateKey object
        
        :param p: prime number
        :param q: prime number different from p
        :return: returns nothing
        """
        self.lamb = (p-1) * (q-1)
        self.mu = modinv(self.lamb, (p * q))
      
    def saveToFile (self, filename="priv.key"):
        """
        Saves PrivateKey into file
        
        :param filename: file to save, default = priv.key
        :return: returns nothing
        """
        key_file = open(filename, "w")
        key_file.write(str(self.lamb) + ";" + str(self.mu))
        key_file.close()
        
    def loadKey(self, filename="priv.key"):
        """
        Loads PrivateKey from file
        
        :param filename: file to read key from, default = priv.key
        :return: returns nothing
        """
        try:
            key_file = open(filename, "r")
            data = key_file.read()
            aux = data.split(";")
            self.lamb = int(aux[0])
            self.mu = int(aux[1])
        except:
            raise Exception("could not load key from file: " + filename)
        
class PublicKey():
    """
    Object for a public key on paillier's cryptosystem
    """
    def __init__ (self, p, q):
        """
        Construct a new PublicKey object
        
        :param p: prime number
        :param q: prime number different from p
        :return: returns nothing
        """
        self.n = p * q
        self.n_sq = self.n * self.n
        self.g = self.n + 1
    
    def loadKey (self, filename="pub.key"):
        """
        Loads PublicKey from file
        
        :param filename: file to read key from, default = pub.key
        :return: returns nothing
        """
        try:
            key_file = open(filename, "r")
            data = key_file.read()
            aux = data.split(";")
            self.n = int(aux[0])
            self.n_sq = int(aux[1])
            self.g = int(aux[2])
        except:
            raise Exception("could not load key from file: " + filename)
    
    def saveToFile (self, filename="pub.key"): 
        """
        Saves PublicKey into file
        
        :param filename: file to save, default = pub.key
        :return: returns nothing
        """
        key_file = open(filename, "w")
        key_file.write(str(self.n) + ";" + str(self.n_sq) + ";" + str(self.g))
        key_file.close()


smallprimes = (2,3,5,7,11,13,17,19,23,29,31,37,41,43,47,53,59,61,67,71,73,79,83,89,97)

def egcd(a, b):
    """
    Extended Euclidean algorith, computes the greatest common diviser and the 
    coefficients of Bezout's identity.
    Source: https://en.wikipedia.org/wiki/Extended_Euclidean_algorithm
    
    :param a: a value
    :param b: b value
    :return: greatest common divisor and coefficients of Bezout's identity
    """
    if a == 0:
        return (b, 0, 1)
    else:
        g, y, x = egcd(b % a, a)
        return (g, x - (b // a) * y, y)

def modinv(a, m):
    """
    Calculates the multiplicative inverse of a in modulo p
    Source: http://code.activestate.com/recipes/576737-inverse-modulo-p/)

    :param a: a value
    :param m: modulo
    :return: b, such that (a * b) % m = 1 
    """
    g, x, y = egcd(a, m)
    if g != 1:
        raise Exception('modular inverse does not exist')
    else:
        return x % m

def decompose(n):     
    """
    Decomposes a number n, such that n = (2^s) * m
    
    :param n: number to decompose
    :return: s, m
    """
    binary_rep = list(bin(n)[2:])
    binary_rep.reverse()
    s = 0
    while(binary_rep[s] == "0"):  ##find last occurance of a bit 1
        s += 1
    return (s, n>>s)  # = n/(2**s))

def myExp(base,exponent,modulus):
    """
    Optimized function to calculate (base ^ exponent) % modulus
    
    :param base: base number
    :param exponent: exponent number
    :param modulus: modulos number
    :return: (base^exponent) % modulus
    """
    result = 1
    while exponent > 0:
        if exponent & 1 == 1:
            result = (result * base) % modulus
        exponent = exponent >> 1
        base = (base * base) % modulus
    return result

def isPrime(p):
    """
    Rabin Millers algorithm to test if a number is prime
    source: https://rosettacode.org/wiki/Miller%E2%80%93Rabin_primality_test#Python
    
    :param p: number to evaluate if prime
    :return: boolean indicating if p is prime or not
    """
    for sp in smallprimes:
        if p == sp:
            return True
        if p % sp == 0:
            return False
    n_tries = 50
    s, m = decompose(p-1)
    while (n_tries > 0):
        n_tries -= 1
        a = random.randrange(2, p-2)
        x = myExp(a,m,p)
        if x == 1 or x == p-1: ##probably prime
            continue
        prime_flag = False
        for _ in xrange(1, s):
            x = myExp(x, 2, p)
            if x == 1: ## p is not prime
                return False
            elif x == p-1:
                prime_flag = True
                break
        if not prime_flag:
            return False
    return True
            

def generatePrime(size):
    """
    Generates a random prime around size bits:
    
    :param size: number of bits of the prime
    :return: prime number
    """
    while True:
        possible_prime = random.randrange(2 ** (size-1) + 1, 2 ** size) | 1 ## | 1 converts in odd number if pair
        if isPrime(possible_prime):
            return possible_prime
    
def generateKeys(bits=256):
    """
    Generates a key pair and stores it in priv.key and pub.key files
    
    :param bits: key size in bits, default 256
    :return: tuple of private key and public key objects
    """
    #print "generating first prime number"
    p = generatePrime(bits/2)
    #print "generating second prime number"
    q = generatePrime(bits/2)
    
    assert p != q
    #print p, "\n", q
    assert gcd(p*q, (p-1)*(q-1)) == 1
     
    priv = PrivateKey(p, q)
    pub = PublicKey(p, q)
    
    priv.saveToFile()
    pub.saveToFile()
    
    return priv, pub
    
def encrypt(pub, plain):
    """
    Encrypts a message
    
    :param pub: public key object
    :param plain: message to encrypt
    :return: encrypted message
    """
    ##according to source, it is required to generate a random, however encryption works fine even if r is not random.
    ## is it more safe to generate a prime r?...
    while True: 
        r = generatePrime(long(round(math.log(pub.n, 2))))
        if r > 0 and r < pub.n:
            break
    x = myExp(r, pub.n, pub.n_sq)
    cipher = (myExp(pub.g, plain, pub.n_sq) * x) % pub.n_sq
    return cipher
    

    
def decrypt(priv, pub, cipher):
    """
    Decrypts an encrypted message
    
    :param priv: private key object
    :param pub: public key object
    :param cipher: encrypted message
    :return: plain text of cipher message
    """
    x = myExp(cipher, priv.lamb, pub.n_sq) - 1
    plain = ((x // pub.n) * priv.mu) % pub.n
    return plain    
    
def e_add(pub, a, b):
    """
    Adds two cipher texts
    
    :param pub: public key object
    :param a: cipher value of a
    :param b: cipher value of b
    :return: a + b, encrypted
    """
    return a * b % pub.n_sq
    
def e_add_const(pub, a, n):
    """
    Adds cipher a to constant n
    
    :param pub: public key object
    :param a: cipher value of a
    :param n: constant n
    :return: a + n, encrypted
    """
    return a * myExp(pub.g, n, pub.n_sq) % pub.n_sq
    
def e_mul_const(pub, a, n):
    """
    Multiplies cipher a by constant n
    
    :param pub: public key object
    :param a: cipher value of a
    :param n: constant n
    :return: a * b, encrypted
    """
    return myExp(a, n, pub.n_sq)
    
    


    



    