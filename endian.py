
class Endian:
    """A class used to handle big-little endian in byte/long format"""

    def __init__(self, n):
        """Get the value in _little endian_
        
        TODO: many type: isistance"""

        self.b_little = n
        self.b_big = n[::-1]
        self.i_little = int(self.b_little.encode('hex'), 16)  # Byte->int "\x01"->"01"->1
        self.i_big = int(self.b_big.encode('hex'), 16)

    def blittle(self):
        """Return n in the byte little endian format"""

        return self.b_little
    
    def bbig(self):
        """Return n in the byte big endian format"""
        
        return self.b_big

    def ilittle(self):
        """Return n in the int little endian format"""
        
        return self.i_little
    
    def ibig(self):
        """Return n in the int big endian format"""
        
        return self.i_big
    
    @staticmethod
    def shex():
        """Return the string hex format"""

        return ":".join("{:02x}".format(ord(c)) for c in s)
