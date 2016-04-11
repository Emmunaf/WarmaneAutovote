#!/usr/bin/python
from socket import *
import hashlib
from time import *
from binascii import *

try:
    import _srp as srp
except:
    print "Need py_srp"
    exit(1)


class Mpacket:
    def hex_print(self, data):
        b = ""
        for i in range(0, len(data)):
            b += "%02x" % ord(data[i])
        return b

    def LoginPacket(self, username):

        packet = "\x00"  # Opcode
        packet += "\x08"  # da wireshark 
        packet += chr(30 + len(username))
        packet += "\x00\x57\x6f\x57\x00"  # Game name: <WoW>
        packet += "\x03\x03\x05"  # Version[1,2,3]: <335>
        packet += "\x34\x30"  # Build: <12340>
        packet += "\x36\x38\x78\x00"  # Platform: <x86>
        packet += "\x6e\x69\x57\x00"  # O.S. : <Win>
        packet += "\x53\x55\x6e\x65"  # Country: <enUS>
        packet += "\x3c\x00\x00\x00"  # Timezone bias: <60>
        packet += "\xc0\xa8\x01\x02"  # IP address: <192.168.1.2> #?? Need real local one, or is it the same?
        packet += chr(len(username))
        packet += username.upper()
        # packet_size = 29 #+
        return packet

    def PasswordPacket_(self, M1, A):
        packet = "\x01"
        #CRC = "\xd7\x6e\x37\x86\x26\x08\xf8\x0f\x72\xec\xdc\x84\xe3\xfd\x73\x65\xdc\x68\x4e\xcd"  # i dont know how to calculate it...
        CRC = "\xa4\x1f\xd3\xe0\x1f\x72\x40\x46\xa7\xd2\xe7\x44\x9e\x1d\x36\xcf\xaf\x72\xa3\x3a"
        NULL_PAD = "\x00\x00"
        A = srp.long_to_bytes(long(A))
        print "------------------------------------------------------------------------------"
        for i in range(0, 32):
            packet += A[i]
        for i in range(0, 20):
            packet += M1[i]
        # packet += chr(i)
        # print packet
        packet += CRC
        packet += NULL_PAD
        return packet

    # None
    def RecvedData(self, data):
        packet_ids = [("AUTH_LOGON_CHALLENGE", "\x00"), ("AUTH_LOGON_PROOF", "\x01")]
        SRP_ = []
        # ....................................................
        packet_id = data[0]
        # ....................................................
        for p in packet_ids:

            if packet_id == p[1]:
                error_ = data[1]
                SRP_.append(data[3:35])  # B, skip 1 field (Length_g)
                SRP_.append(data[36:37])  # g, skip 1 field (Length_n)
                SRP_.append(data[38:38 + 32])  # n
                SRP_.append(data[38 + 32:38 + (32 * 2)])  # s [salt]
                SRP_.append(data[38 + (32 * 2):len(data) - 1])  # CRC
                print p[0] + " with error :" + hex(ord(error_))
                print "SRP B :" + self.hex_print(SRP_[0]) + " " + str(len(SRP_[0]))
                print "SRP g :" + self.hex_print(SRP_[1]) + " " + str(len(SRP_[1]))
                print "SRP N :" + self.hex_print(SRP_[2]) + " " + str(len(SRP_[2]))
                print "SRP s :" + self.hex_print(SRP_[3]) + " " + str(len(SRP_[3]))
                print "CRC :" + self.hex_print(SRP_[4]) + " " + str(len(SRP_[4]))
                return SRP_
            if packet_id == p[2]:
                print "We got it!"


X = Mpacket()
host = "54.213.244.47"
port = 3724

user = "alexlorens".upper()
pass_ = "lolloasd".upper()

sck = socket(AF_INET, SOCK_STREAM)
sck.connect((host, port))
n_make = ""
b_make = ""
s_make = ""
sck.send(X.LoginPacket(user))
SRP_ARRAY = X.RecvedData(sck.recv(1024))
############################################################################
g = srp.bytes_to_long(SRP_ARRAY[1])
#g = srp.bytes_to_long("\x07")
N = srp.bytes_to_long(SRP_ARRAY[2])
#N = srp.bytes_to_long("\xb7\x9b\x3e\x2a\x87\x82\x3c\xab\x8f\x5e\xbf\xbf\x8e\xb1\x01\x08\x53\x50\x06\x29\x8b\x5b\xad\xbd\x5b\x53\xe1\x89\x5e\x64\x4b\x89")
hash_class = srp._hash_map[srp.SHA1]

#k =  srp.H(hash_class, N, g)
k = 3
I = user
p = pass_
a = srp.get_random(32)
A = pow(g, a, N)
v = None
M = None
K = None
H_AMK = None
s = srp.bytes_to_long(SRP_ARRAY[3])
#s = srp.bytes_to_long("\x2d\xc6\xb5\xfc\x0c\xae\x6f\x0b\x26\x2f\x10\x2c\xce\xe3\x91\x0c\x34\x87\x56\x0f\x19\x0e\x8b\x41\x9d\xee\x93\x67\x9b\x6b\x30\x8d")
B = srp.bytes_to_long(SRP_ARRAY[0])
#B = srp.bytes_to_long("\x2b\x39\x9c\xdd\x64\xb5\xa8\x17\x7f\x40\x32\xef\x0b\x07\xd5\x84\xe2\xb6\x3e\x49\x63\x04\xfe\x14\x0e\x95\xd7\x52\x67\xf7\xd7\x30")
# _authenticated = False
if (B % N) == 0:
    print "Error"
u = srp.H(hash_class, A, B)
x = srp.gen_x(hash_class, s, I, p)##
v = pow(srp.reverse(g), srp.reverse(x), srp.reverse(N))
S = pow((B - k * v), a + u * x, N)
#print("S: ", S)
K = hash_class(srp.long_to_bytes(S)).digest()
M = srp.calculate_M(hash_class, N, g, I, s, A, B, K)
############################################################################
sck.send(X.PasswordPacket_(M, A))
sck.recv(1024)  # REALM_AUTH_NO_MATCH...:(
sck.send("\x10\x00\x00\x00\x00")
print sck.recv(1024)
# x.RecvedData(sck.recv(1024))
