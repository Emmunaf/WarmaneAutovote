import os
import hashlib
from endian import Endian


class Srp:
    """A class for using an edited SRP6, created to work with WoW Logon system."""

    def __init__(self, N, g, I, p, s, B, k=3):
        """Initialize the class
        """

        # N,g,s,B should be in bytestring format ("\x01\x10\x03")
        self.a = Endian(os.urandom(32))  # Used to calculate A
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
        # Hash the even bytes of S (session key)
        hash_object = hashlib.sha1(s_bytes[::2])
        even_hashed = hash_object.digest()
        # Hash the odd bytes of S
        hash_object = hashlib.sha1(s_bytes[1::2])
        odd_hashed = hash_object.digest()
        K = ""
        # Create K as alternate string concatenation
        for o, e in zip(even_hashed, odd_hashed):
            K += o + e  # K = odd[0],even[0],odd[1],..
        self.K = Endian(K)
        return self.K

    def gen_M(self):
        """Generate M (client side)"""

        hN = hashlib.sha1(self.N.blittle()).digest()
        hg = hashlib.sha1(self.g.blittle()).digest()
        hN_xor_hg = ''.join(chr(ord(hN[i]) ^ ord(hg[i])) for i in range(0, len(hN)))
        try:
            hash_object = hashlib.sha1(hN_xor_hg)
            hash_object.update(hashlib.sha1(self.I).digest())
            hash_object.update(self.s.b_little)
            hash_object.update(self.A.b_little)
            hash_object.update(self.B.b_little)
            hash_object.update(self.K.b_little)
        except AttributeError:
            raise ValueError("You need to call gen_K() first!")

        self.M = Endian(hash_object.digest())
        return self.M

    @staticmethod
    def int_to_bytes(n):
        l = []
        x = 0
        off = 0
        while x != n:
            b = (n >> off) & 0xFF
            l.append(chr(b))
            x |= b << off
            off += 8
        l.reverse()
        return ''.join(l)
