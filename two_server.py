import random
from paillier import *
from boosted_paillier import *

"""
This code implements the two server delegation of the boosted paillier
"""

class CipherTwoServer():
    """
    Object for two server cipher
    """
    def __init__(self, c, b):
        """
        Creates a CipherTwoServer
        :param c: level 1 or 2 cipher
        :param b: random value
        """
        self.alpha = c
        self.beta = b
    
    def create_level1_cipher(self, m, pub):
        """
        Creates a object based on the encryption of m
        The object has 3 attributes: a, beta and b, computed as
        a = m - b, enc(b), b, respectively
        
        :param m: message to encrypt
        :param pub: public key object
        :return: returns nothing
        """
        r = random.randrange(256, pub.n)
        c = CipherLevel1(1,1)
        c.prepare_message_given_random(pub, m, r)
        self.alpha = c
        self.beta = r
    
    def get_value(self, priv, pub):
        """
        Decrypts the true value of the cipher.
        Computation depends on level of the cipher
        :return" returns decrypted value
        """
        if isinstance(self.alpha, CipherLevel1):
            return (self.alpha.a + self.beta) % pub.n
        else:
            aux = decrypt(priv, pub, self.alpha)
            return (aux + self.beta) % pub.n
            
    
def server1_add1(c1, c2, pub):
    """
    Computation on server 1 for two level 1 two server ciphertext addition
    :param c1: level 1 cipher
    :param c2: level 1 cipher
    :param pub: public key object
    :return: level 1 cipher
    """
    return add1 (c1, c2, pub)

def server2_add1(b1, b2, pub):
    """
    Computation on server 2 for two level 1 cipher addition
    :param b1: b component of cipher
    :param b2: b component of cipher
    :param pub: public key object
    :return: another b
    """
    return (b1 + b2) % pub.n
        
def ts_add1(c1, c2, pub):
    """
    Receives two level 1 ciphertexts and computes their sum
    Sends different parts to each server
    :param c1: level 1 two server ciphertext
    :param c2: level 1 two server ciphertext
    :param pub: public key object
    :return: level 1 two server ciphertext
    """
    a = server1_add1(c1.alpha, c2.alpha, pub)
    b = server2_add1(c1.beta, c2.beta, pub)
    return CipherTwoServer(a, b)
    
def server1_mult(c1, c2, pub):
    """
    Computation on server 1 for two level 1 two server ciphertext multiplication
    :param c1: level 1 cipher
    :param c2: level 1 cipher
    :param pub: public key object
    :return: alpha part of level 2 cipher
    """
    c = mult1 (c1, c2, pub)
    return c.a
    
def server2_mult(b1, b2, pub):
    """
    Computation on server 2 for two level 1 two server ciphertext multiplication
    :param c1: b component of cipher
    :param c2: b component of cipher
    :param pub: public key object
    :return: another b
    """
    return (b1 * b2) % pub.n
    
def ts_mult(c1, c2, pub):
    """
    Receives two level 1 two server ciphertext and computes their multiplication
    Sends different parts to each server
    :param c1: level 1 two server ciphertext
    :param c2: level 1 two server ciphertext
    :param pub: public key object
    :return: level 2 two server ciphertext
    """
    a = server1_mult(c1.alpha, c2.alpha, pub)
    b = server2_mult(c1.beta, c2.beta, pub)
    return CipherTwoServer(a, b)
    
def server1_add2 (c1, c2, pub):
    """
    Computation on server 1 for two level 2 two server ciphertext addition
    
    :param c1: alpha of cipher 1
    :param c2: alpha of cipher 2
    :param pub: public key object
    :return: level 2 cipher two server
    """
    #return (c1 + c2) % pub.n
    return e_add(pub, c1, c2)
    
def server2_add2 (b1, b2, pub):
    """
    Computation on server 2 for two level 2 cipher addition
    
    :param b1: b component of cipher
    :param b2: b component of cipher
    :param pub: public key object
    :return: another b
    """
    return (b1 + b2) % pub.n
    
def ts_add2 (c1,c2, pub):
    """
    Receives two level 2 two server ciphertexts and computes their multiplication
    Sends different parts to each server
    
    :param c1: level 2 two server ciphertext
    :param c2: level 2 two server ciphertext
    :param pub: public key object
    :return: level 2 two server ciphertext
    """
    
    a = server1_add2(c1.alpha, c2.alpha, pub)
    b = server2_add2(c1.beta, c2.beta, pub)
    return CipherTwoServer(a,b)
    

    
print "****testing two server boosted paillier:****"    

priv, pub = generateKeys(256)
m1 = 11
m2 = 5 
    
c1 = CipherTwoServer(-1,-1)
c2 = CipherTwoServer(-1,-1)

c1.create_level1_cipher(m1, pub)
c2.create_level1_cipher(m2, pub)

add_c = ts_add1(c1, c2, pub)
print "two level 1 ciphers sum: ", m1, " + ", m2, " = ", add_c.get_value(priv, pub)
mult_c = ts_mult(c1, c2, pub)
print "two level 1 ciphers multiplication: ", m1, " * ", m2, " = ", mult_c.get_value(priv, pub)
add2_c = ts_add2(mult_c, mult_c, pub)
val = mult_c.get_value(priv, pub)
print "two level 2 ciphers sum: ", val, " + ", val, " = ", add2_c.get_value(priv,pub)

    
    
    
    
    
    
    
    