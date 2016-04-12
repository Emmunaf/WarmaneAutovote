import os
import hashlib
from endian import Endian


class Srp:
    """A class for using an edited SRP6, created to work with WoW Logon system.
        
        """

    def __init__(self, N, g, I, p, s, B, k=3):
        """Initialize the class
            """

        # N,g,s,B should be in bytestring format ("\x01\x10\x03")
        self.N = Endian(N)  # N is a safe prime, sended by server (all op. are mod N)
        self.g = Endian(g)  # g is a generator of the multiplicative group
        self.I = I  # Username
        self.p = p  # Password
        self.s = Endian(s)  # Salt, generated and sent by server
        self.B = Endian(B)  # Public ephemeral value (server generated)
        self.k = Endian(self.int_to_bytes(k))  # Multiplier parameter (k = 3 in SRP6, k = H(N, g) in SRP-6a)
        if self.B.ibig() % self.N.ibig() == 0:
            raise Exception()

    def gen_A(self):
        """Generate A as defined in SRP6: A= ModPow(g, a, N)
            
            A is the  Public ephemeral value (client generated)
        """

        self.a = Endian(os.urandom(32))  # Used to calculate A
        A = pow(self.g.ibig(), self.a.ibig(), self.N.ibig())  # A is Big Endian
        self.A = Endian(self.int_to_bytes(A)[::-1])  # self.A is converted to Endian(little_end)
        return self.A

    def gen_u(self):
        """Calculate the random scrambling parameter u = H(A,B)"""

        hash_object = hashlib.sha1()
        try:
            hash_object.update(self.A.blittle())
        except AttributeError:
            raise ValueError("You need to generate A first.\nYou can do this calling gen_A()")
        hash_object.update(self.B.blittle())
        hashed = hash_object.digest()
        self.u = Endian(hashed)
        return self.u

    def gen_S(self):
        """Calculate client session key
            
            x = H(s, H(I:P))
        """

        hash_object = hashlib.sha1(self.I + ':' + self.p)
        ih = hash_object.digest()  # WoW requires to gen x with I=H(user:pass))
        hash_object = hashlib.sha1(self.s.blittle())
        hash_object.update(ih)
        x = Endian(hash_object.digest())
        v = pow(self.g.ibig(), x.ibig(), self.N.ibig())  # Note: v is an int big-Endian
        try:
            S = pow(self.B.ibig() - self.k.ibig() * v,  # v is already int big-Endian
                    self.a.ibig() + self.u.ibig() * x.ibig(),
                    self.N.ibig())  # Note: S is an int big-Endian
        except AttributeError:
            raise ValueError("You need to generate u first.\nYou can do this calling gen_u()")
        self.S = Endian(self.int_to_bytes(S)[::-1])
        return self.S

    def gen_K(self):
        """Generate K by S with SHA1 Interleaved"""

        try:
            s_bytes = self.S.blittle()
        except AttributeError:
            raise ValueError("You need to generate S first.\nYou can do this calling gen_S()")
        # Hash the odd bytes of S (session key)
        hash_object = hashlib.sha1(s_bytes[::2])
        odd_hashed = hash_object.digest()
        # Hash the even bytes of S
        hash_object = hashlib.sha1(s_bytes[1::2])
        even_hashed = hash_object.digest()
        K = ""
        # Create K as alternate string concatenation
        for o, e in zip(odd_hashed, even_hashed):
            K += o + e  # K = odd[0],even[0],odd[1],..

        return Endian(K)

    @staticmethod
    def int_to_bytes(n):
        l = []
        x = 0
        off = 0
        while x != n:
            b = (n >> off) & 0xFF
            l.append(chr(b))
            x = x | (b << off)
            off += 8
        l.reverse()
        return ''.join(l)


def test():
    N = '\xb7\x9b>*\x87\x82<\xab\x8f^\xbf\xbf\x8e\xb1\x01\x08SP\x06)\x8b[\xad\xbd[S\xe1\x89^dK\x89'
    g = '\x07'
    I = 'ALEXLORENS'
    p = 'LOLLOASD'
    s = '\xa9zOJ|\xed\xd3\x7f8\xcd\x97]\x02\x13OOU\xa3^\xb4a\xfeF\xd4\xf8\x1e\x06\x9ax\xd9Y\x9b'
    B = '\xe2\x12L<\x800\xe5\xd5V>\xd5\xed\x87M\xde\xf6\x16r\xb5!H\r\x94F\x89\x8aGW\x03\xeb\xa9\x85'
    # a  fissato, ricorda di togliere
    # You need to modify _a_ to do tests
    tests = Srp(N, g, I, p, s, B, k=3)
    A = tests.gen_A()
    u = tests.gen_u()
    S = tests.gen_S()
    print("A:", A.ilittle())
    print("u:", u.ilittle())
    print("S:", S.ilittle())
    K = tests.gen_K()
    print("K:", K.blittle())


#test()
