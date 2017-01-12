import random
from paillier import *

"""
This code implements a boosting strategy to transfrom a paillier cryptosystem into a full-homomorphic cipher
The code was implemented using as reference paper:
Boosting Linearly-Homomorphic Encryption to Evaluate Degree-2 Functions on Encrypted Data
"""

class CipherLevel1():
    """
    Level 1 cipher object
    """
    
    def __init__(self, a1, b1):
        """
        Constructs a level 1 cipher object
        """
        self.a = a1
        self.b = b1
    
    def prepare_message(self, pub, m):
        """
        Prepares a level 1 cipher for a message.
        Generates a random r and stores in the object a and b
        computed as: a = m-r, b = enc(r)
        :param pub: public key object
        :param m: value to create cipher
        :return: returns nothing
        """
        r = random.randrange(256, pub.n)
        b = encrypt(pub, r)
        a = (m-r) % pub.n
        self.a = a
        self.b = b
    
        
    def prepare_message_given_random(self, pub, m, r):
        """
        Prepares a level 1 cihper for a message given a already random number
        
        :param pub: public 
        :param m: value to create cipher
        :param r: random vlaue to use
        :return: returns nothing
        """
        b = encrypt(pub, r)
        a = (m-r) % pub.n
        self.a = a
        self.b = b
        
    def get_value(self, priv, pub):
        """
        Retrieves the original value of a level 1 cipher.
        
        :param priv: private key object
        :param pub: public key object
        :return: returns the original value
        """
        val = (self.a + decrypt(priv, pub, self.b)) % pub.n
        return val
        
class CipherLevel2():
    """
    Level 2 cipher object, which consists of a value a and a list of lists of values B
    """
    
    def __init__(self, a1, b1):
        """
        constructs a Cipherlevel 2 object
        """
        self.a = a1
        self.b = b1
    
    def get_value(self, priv, pub):
        """
        Retrieves the original value of a level 2 cipher.
        
        :param priv: private key object
        :param pub: public key object
        :return:
        """
        aux = decrypt(priv, pub, self.a)
        total = 0
        for x in self.b:
            x1 = decrypt(priv, pub, x[0])
            x2 = decrypt(priv, pub, x[1])
            x = (x1 * x2) % pub.n
            total += x
        val = (aux + total) % pub.n
        return val

def add1 (c1, c2, pub):
    """
    Adds two level 1 ciphers and returns a 1 levle cipher
    
    :param c1: level 1 cipher
    :param c2: level 1 cipher
    :param pub: publick key object
    :return: return level 1 cipher
    """
    
    a = (c1.a + c2.a) % pub.n
    b = e_add(pub, c1.b, c2.b)
    c = CipherLevel1(a, b)
    return c
    
def mult1 (c1, c2, pub):
    """
    Multiplies two level 1 ciphers and returns a level 2 cipher
    
    :param c1: level 1 cipher
    :param c2: level 1 cipher
    :param pub: publick key object
    :return: return level 2 cipher
    """
    
    p1 = (c1.a * c2.a) % pub.n
    p1 = encrypt(pub, p1)
    p2 = e_mul_const(pub, c2.b, c1.a)
    p3 = e_mul_const(pub, c1.b, c2.a)
    a = e_add(pub, p1, p2)
    a = e_add(pub, a, p3)
    
    c = CipherLevel2(a, [[c1.b,c2.b]])
    return c
    

    
def add2 (c1, c2, pub):
    """
    Adds two level 2 ciphers and returns a level 2 cipher
    
    :param c1: level 2 cipher
    :param c2: level 2 cipher
    :param pub: publick key object
    :return: return level 2 cipher
    """
    a = e_add(pub, c1.a, c2.a)
    b = c1.b + c2.b
#    [b.append(x) for x in c1.b]
#    [b.append(x) for x in c2.b]
    c = CipherLevel2(a, b)
    return c
    
def cmult1 (const, c1, pub):
    """
    Multiplies a constant by a level 1 cipher
    
    :param const: constant to multiply
    :param c1: level 1 cipher
    :param pub: publick key object
    :return: level 1 cipher
    """
    a = (c1.a * const) % pub.n
    #b = (c1.b * const) % pub.n
    b = e_mul_const(pub, c1.b, const)
    c = CipherLevel1(a,b)
    return c
    
def cmult2(const, c1, pub):
    """
    Multiplies a constant by a level 2 cipher
    
    :param const: constant to multiply
    :param c1: level 2 cipher
    :param pub: publick key object
    :return: level 2 cipher
    """
    #a = (c1.a * const) % pub.n
    a = e_mul_const(pub, c1.a, const)
    b = []
    for x in c1.b:
        #b_x = (x[0] * const) % pub.n
        b_x = e_mul_const(pub, x[0], const)
        b.append([b_x, x[1]])
    c = CipherLevel2(a,b)
    return c

def rerand1(c1, pub):
    """
    Re-randomizes a level 1 cipher, this step is crucial to achieve circuit privacy
    
    :param c1: level 1 cipher
    :param pub: public key object
    :return: level 1 cipher
    """
    r = random.randrange(256, pub.n)
    b1 = encrypt(pub, r)
    b = e_add(pub, b1, c1.b)
    a = (c1.a - r) % pub.n
    c = CipherLevel1(a,b)
    return c
    
def rerand2(c1, pub):
    """
    Re-randomizes a level 2 cipher, this step is crucial to achieve circuit privacy
    Not working, need to understand how to add negative numbers!!!
    :param c1: level 2 cipher
    :param pub: public key object
    :return: level 2 cipher
    """
    raise("Method is not complete!")
    return 1

key_size = 256
priv, pub = generateKeys(key_size)

m1 = 5
m2 = 10
const = 3

print "****testing original paillier:***"
x = encrypt(pub, m1)
x1 = decrypt(priv, pub, x)
assert x1 == m1 ##verify decrpytion    

y = encrypt(pub, m2)
z = e_add(pub, x, y)   
print "two ciphers sum: ", m1, " + ", m2, " = ", decrypt(priv, pub, z)
z = e_add_const(pub, x, const)
print "add constant to cipher: ", m1, " + ", const, " = ", decrypt(priv, pub, z)
z = e_mul_const(pub, x, const)
print "multiply constant by cipher: ", m1, " . ", const, " = ", decrypt(priv, pub, z)


print "\n****testing boosted paillier:****"

c1 = CipherLevel1(-1,-1)
c2 = CipherLevel1(-1,-1)
c1.prepare_message(pub, m1)
c2.prepare_message(pub, m2)

add_c = add1(c1, c2, pub)
print "two level 1 ciphers sum: ", m1, " + ", m2, " = ", add_c.get_value(priv, pub)
assert (m1 + m2) == add_c.get_value(priv, pub) 
mult_c = mult1(c1, c2, pub)
print "two level 1 ciphers multiplication: ", m1, " * ", m2, " = ", mult_c.get_value(priv, pub)
assert len(bin(m1 * m2)) < key_size -2, "Multiplication is outside of the keyspace, lower the values!"
assert (m1 * m2) == mult_c.get_value(priv, pub) 
const_mult = cmult1(const, c1, pub)
print "level 1 cipher by constant multiplication: ", m1, " * ", const, " = ", const_mult.get_value(priv, pub)
assert (const * m1) == const_mult.get_value(priv, pub)
add2_c = add2(mult_c, mult_c, pub)
val = mult_c.get_value(priv, pub)
print "two level 2 ciphers sum: ", val, " + ", val, " = ", add2_c.get_value(priv,pub)
assert (val + val) == add2_c.get_value(priv,pub) 
mult2_c = cmult2(const, add2_c, pub)
print "level 2 cipher by constant multiplication: ", const, " * ", add2_c.get_value(priv, pub), " = ", mult2_c.get_value(priv, pub) 
assert (const * add2_c.get_value(priv, pub)) == mult2_c.get_value(priv, pub)




