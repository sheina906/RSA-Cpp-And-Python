class rsa:
    def __init__(self, n, e, d):
        self._pub, self._priv, self._n = e, d, n
    
    def encrypt(self, msg):
        return pow(msg, self._pub, self._n)
    
    def decrypt(self, enc):
        return pow(enc, self._priv, self._n)