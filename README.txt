These files implement the encryptition scheme presented in paper Boosting Linearly-Homomorphic Encryption to Evaluate Degree-2 Functions on Encrypted Data.
The code was tested in Python 2.7.12 (no external libraries required). The implementation is divided in 4 modules:

- paillier.py: This one implements the paillier crypto system.

- boosted_pailier.py: Implements tbe transformation to make paillier a full homomorphic cryptosystem.
					Corresponds to section 4 in the paper

- two_server.py: Implements the cryptosystem in such way that it is possible to divide computation across two servers. Corresponds to section 5.2 in the paper

- two_server_third_degree.py: Improves the cryptosystem to deal with 3rd degree polynomials. Corresponds to section 5.3 in the paper

Each file has a .html that describes each function and class. Furthermore, to ease testing, there's an example of computations on each file.

---Known issues---

- The rerand of a level 2 function was not implemented because there were some problems dealing with the subtraction part of the formula. I was not capable to find the error and correct it
- On the two server third degree the mult2 function does not work correctly. I was not sure how to multiply the last part of the formula, and I was not able to figure it out.

