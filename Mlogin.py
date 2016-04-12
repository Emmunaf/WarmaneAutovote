#!/usr/bin/python
# Thanks: Glusk for the GREAT help
#       karapidiola for the base script

from socket import *
import hashlib

try:
    import _srp as srp
except:
    print("Need py_srp")
    exit(1)


def generate_K(S):
    """Generate K from S with SHA1 Interleaved"""

    s_bytes = srp.long_to_bytes(S)
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

    return K


class Mpacket:
    def hex_print(self, data):
        b = ""
        for i in range(0, len(data)):
            b += "%02x" % ord(data[i])
        return b

    def alchallenge_packet(self, username):

        packet = "\x00"  # Opcode (Auth Logon Challenge)
        packet += "\x08"  # (Error) da wireshark 
        packet += chr(30 + len(username))
        packet += "\x00\x57\x6f\x57\x00"  # Game name: <WoW>
        packet += "\x03\x03\x05"  # Version[1,2,3]: <335>
        packet += "\x34\x30"  # Build: <12340>
        packet += "\x36\x38\x78\x00"  # Platform: <x86>
        packet += "\x6e\x69\x57\x00"  # O.S. : <Win>
        packet += "\x53\x55\x6e\x65"  # Country: <enUS>
        packet += "\x3c\x00\x00\x00"  # Timezone bias: <60>
        packet += "\xc0\xa8\x01\x02"  # IP address: <192.168.1.2> #?? Need real local one, or is it the same?
        packet += chr(len(username))  # SRP I length
        packet += username.upper()  # SRP I value
        return packet

    def alproof_packet(self, M1, A):

        packet = "\x01"  # Opcode (Auth Logon Proof)
        # For CRC don't need real value (annoying, sha1 files)
        CRC = "\xa4\x1f\xd3\xe0\x1f\x72\x40\x46\xa7\xd2\xe7\x44\x9e\x1d\x36\xcf\xaf\x72\xa3\x3a"
        NULL_PAD = "\x00\x00"
        A = srp.long_to_bytes(long(A))
        print "------------------------------------------------------------------------------"
        for i in range(0, 32):
            packet += A[i]
        for i in range(0, 20):
            packet += M1[i]
        packet += CRC
        packet += NULL_PAD
        return packet

    def decode_packet(self, data):

        opcodes = [("AUTH_LOGON_CHALLENGE", "\x00"), ("AUTH_LOGON_PROOF", "\x01")]
        srp_vals = []
        opcode = data[0]

        for p in opcodes:
            if opcode == p[1]:
                error = data[1]
                srp_vals.append(data[3:35])  # B, skip 1 field (Length_g)
                srp_vals.append(data[36:37])  # g, skip 1 field (Length_n)
                srp_vals.append(data[38:38 + 32])  # n
                srp_vals.append(data[38 + 32:38 + (32 * 2)])  # s [salt]
                srp_vals.append(data[38 + (32 * 2):len(data) - 1])  # CRC
                print p[0] + " with error :" + hex(ord(error))
                print "SRP B :" + self.hex_print(srp_vals[0]) + " " + str(len(srp_vals[0]))
                print "SRP g :" + self.hex_print(srp_vals[1]) + " " + str(len(srp_vals[1]))
                print "SRP N :" + self.hex_print(srp_vals[2]) + " " + str(len(srp_vals[2]))
                print "SRP s :" + self.hex_print(srp_vals[3]) + " " + str(len(srp_vals[3]))
                print "CRC :" + self.hex_print(srp_vals[4]) + " " + str(len(srp_vals[4]))
                print srp_vals
                return srp_vals
            if opcode == p[2]:
                print "We got it!"


X = Mpacket()

# Server data
host = "54.213.244.47"
port = 3724

# Login data (alexlorens, lolloasd) is a testing account
user = "alexlorens".upper()
password = "lolloasd".upper()

sck = socket(AF_INET, SOCK_STREAM)
sck.connect((host, port))
n_make = ""
b_make = ""
s_make = ""
sck.send(X.alchallenge_packet(user))  # Send Auth Logon Challenge
SRP_ARRAY = X.decode_packet(sck.recv(1024))  # Read SRP value for sending Logon Proof
############################################################################
g = srp.bytes_to_long(SRP_ARRAY[1])
N = srp.bytes_to_long(SRP_ARRAY[2])
hash_class = srp._hash_map[srp.SHA1]  # Using sha1 hashing for everything except K (Sha1-Interleaved)
k = 3  # SRP-6
I = user
p = password
# Generate A
a = srp.get_random(32)
A = srp.reverse(pow(srp.reverse(g), srp.reverse(a), srp.reverse(N)))  # Big endian
#
## PRINT TEST1
print("Calcolo A")
print ('a:', a)
print ('g:', SRP_ARRAY[1])
print ('N:', SRP_ARRAY[2])
print ('A:', A)
##END PRINT TEST 1
v = None
M = None
K = None
H_AMK = None
s = srp.bytes_to_long(SRP_ARRAY[3])
B = srp.bytes_to_long(SRP_ARRAY[0])
#print('B: ->', B)
#print('B: [bytes_to_long] ->',srp.bytes_to_long(SRP_ARRAY[0]))
#print('B: [reversed, used for calc] ->',srp.reverse(B))
if (B % N) == 0:
    print "Error"
u = srp.H(hash_class, A, B)
x = srp.gen_x(hash_class, s, I, p)  #
v = srp.reverse(pow(srp.reverse(g), srp.reverse(x), srp.reverse(N)))  # Big endian
S = srp.reverse(pow((srp.reverse(B) - srp.reverse(k) * srp.reverse(v)),
                    srp.reverse(a) + srp.reverse(u) * srp.reverse(x), srp.reverse(N)))  # Big endian
## PRINT TEST3
print "--------------####-----------------------"
print("Valori utili")
print ('N:', SRP_ARRAY[2])
print ('g:', SRP_ARRAY[1])
print ('I:', I)
print ('p:', p)
print ('s:', SRP_ARRAY[3])
print ('B:', SRP_ARRAY[0])
print ('[a]:', srp.long_to_bytes(a))


print "---------------####----------------------"
##END PRINT TEST 3

## PRINT TEST2
print "----------------------------------------"
print("Calcolo u, x, S")
print ('u:', u)
print ('x:', x)
print ('v:', v)
print ('S:', S)
print "----------------------------------------"
##END PRINT TEST 2

K = generate_K(S)
print ('K:', K)
M = srp.calculate_M(hash_class, N, g, I, s, A, B, K)
############################################################################
sck.send(X.alproof_packet(M, A))
sck.recv(1024)  # REALM_AUTH_NO_MATCH...:(
sck.send("\x10\x00\x00\x00\x00")
print sck.recv(1024)
# x.RecvedData(sck.recv(1024))
'''Note:
Use little endian for hashing,
Big endian while doing math:
(*,+,^,ModPow,...)
'''
