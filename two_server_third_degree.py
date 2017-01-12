from paillier import *
from boosted_paillier import *

"""
This code implmentes the two server side version, 
improved to support third degree polynomials

"""



class CipherThirdDegree():
    """
    Object for cipher that supports thrid degree polynomials
    """
    def __init__(self, c, b):
        """
        Creates a CipherThirdDegree
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
        elif isinstance(self.alpha, CipherLevel2):
            aux = decrypt(priv, pub, self.alpha.a)
            return (aux + self.beta) % pub.n
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
    :return: level 1 third degree cipher
    """
    a = server1_add1(c1.alpha, c2.alpha, pub)
    b = server2_add1(c1.beta, c2.beta, pub)
    return CipherThirdDegree(a, b)
    
def server1_mult1(c1, c2, pub):
    """
    Computation on server 1 for two level 1 multiplication
    :param c1: level 1 cipher
    :param c2: level 1 cipher
    :param pub: public key object
    :return: level 2 cipher, where b part is another level 2 cipher
    """
    aux_a = mult1 (c1, c2, pub)
    ## need to calculate multiplication of B parts, 
    # however since both are encrypted I think we need 
    #to convert them to level 1 ciphers and them multiply
    #paper does not elaborate on that
    b1 = CipherLevel1(1,1)
    b2 = CipherLevel1(1,1)
    b1.prepare_message(pub, c1.b)
    b2.prepare_message(pub, c2.b)
    aux_b = mult1(b1, b2, pub)
    c = CipherLevel2(aux_a.a, aux_b)
    return c
 
def server2_mult1(b1, b2, pub):
    """
    Computation on server 2 for two level 1 multiplication
    :param b1: b component of cipher
    :param b2: b component of cipher
    :param pub: public key object
    :return: another b
    """
    return (b1 * b2) % pub.n
    
def ts_mult1(c1, c2, priv, pub):
    """
    Computes the multiplication of 2 level 1 cipher
    :param c1: Cipher third degree
    :param c2: Cipher third degree
    :param pub: public key object
    :return: Cipher third degree with level 2 cipher
    """
    aux = server1_mult1(c1.alpha, c2.alpha, pub)
    alpha = CipherLevel2(aux.a, aux.b.get_value(priv, pub))
    beta = server2_mult1(c1.beta, c2.beta, pub)
    c = CipherThirdDegree(alpha, beta)
    return c
    
def server1_add2(c1, c2, pub):
    """
    Computation on server 1 for 2 level 2 sum
    :param c1: level 2 cipher
    :param c2: level 2 cipher
    :param pub: public key object
    :return: level 2 cipher
    """
    alpha = e_add(pub, c1.a, c2.a)
    beta = e_add(pub, c1.b, c2.b)
    c = CipherLevel2(alpha, beta)
    return c
    
def ts_add2(c1, c2, pub):
    """
    Computes the addition of 2 level 2 cipher
    :param c1: Cipher thrid degree
    :param c2: Cipher third degree
    :param pub: public key object
    :return: Cipher third degree of level 2
    """
    alpha = server1_add2(c1.alpha, c2.alpha, pub)
    beta = server2_add1(c1.beta, c2.beta, pub) ##same as add1 so we can reuse function
    c = CipherThirdDegree(alpha, beta)
    return c
    
def server1_mult2(c1, c2, pub):
    """
    Computations on server on for level 1 * level 2 ciphers
    :param c1: level 1 cipher
    :param c2: level 2 cipher
    :param pub: public key object
    :return: two parts to construct level 3 cipher
    """
    #aux = cmult2(c1.alpha, c2, pub)
    aux = e_mul_const(pub, c2.a, c1.a)
    aux2 = e_mul_const(pub, c2.b, c1.a)
    
    ##same thing that happened on mult1
    ##however here we cant send the private key to the server, it would not make any sense
    ##so lets justs send both parts and the client adds them in a final computation
    b1 = CipherLevel1(1,1)
    b2 = CipherLevel1(1,1)
    b1.prepare_message(pub, c1.b)
    b2.prepare_message(pub, c2.b)
    aux3 = mult1(b1, b2, pub)
    #aux3 = mult1 (c1.b, c2.a, pub)
    aux4 = e_add(pub, aux, aux2)
    #delta = e_add(aux3, aux4, pub)
    #return delta
    return aux4, aux3
    
    
def ts_mult2(c1, c2, priv, pub):
    """
    Calculates the multiplication of level 1 by level 2 cipher on two servers
    :param c1: Cipher third degree level 1
    :param c2: Cipher third degree level 2
    :param pub: public key object
    :return: Cipher third degree of level 3
    """
    aux_a, aux_b = server1_mult2(c1.alpha, c2.alpha, pub)
    alpha = e_add(pub, aux_a, aux_b.get_value(priv,pub))
    #alpha = server1_mult2(c1.alpha, c2.alpha, pub)
    beta = server2_mult1(c1.beta, c2.beta, pub) ##same as mult 1
    c = CipherThirdDegree(alpha, beta)
    return c
    
def server1_add3(c1, c2, pub):
    """
    Computation on server 1 for 2 level 3 ciphers adition
    :param c1: level 3 cipher
    :param c2: level 3 cipher
    :param pub: public key object
    """
    return e_add(pub, c1, c2)

def ts_add3(c1, c2, pub):
    """
    Calcutes the adition of 2 level 3 cipher on two servers
    :param c1: Cipher third degree level 3
    :param c2: Cipher third degree level 3
    :param pub: public key object
    :return: returns Cipher third degree level 3
    """
    
    alpha = server1_add3(c1.alpha, c2.alpha, pub)
    beta = server2_add1(c1.beta, c2.beta, pub)
    c = CipherThirdDegree(alpha, beta)
    return c
    
    
    
priv, pub = generateKeys(256)
m1 = 11
m2 = 5 

c1 = CipherThirdDegree(-1, -1)
c2 = CipherThirdDegree(-1, -1)

c1.create_level1_cipher(m1, pub)
c2.create_level1_cipher(m2, pub)

print "*****Testing third degree implementation*****"

add1_c = ts_add1(c1, c2, pub)
print "add 1 test: ", m1, " + ", m2, " = ", add1_c.get_value(priv,pub)
mult1_c = ts_mult1(c1, c2, priv, pub)
print "mult1 test: ", m1, " * ", m2, " = ", mult1_c.get_value(priv, pub)
add2_c = ts_add2(mult1_c, mult1_c, pub)
val = mult1_c.get_value(priv, pub)
print "add2 test: ", val, " + ", val, " = ", add2_c.get_value(priv, pub)
mult2_c = ts_mult2(c1, mult1_c, priv, pub)
print "mult2 test: ", m1, " * ", val, " = ", mult2_c.get_value(priv, pub)
add3_c = ts_add3(mult2_c, mult2_c, pub)
val = mult2_c.get_value(priv, pub)
print "add3 test: ", val, " + ", val, " = ", add3_c.get_value(priv, pub)
    
    
    
