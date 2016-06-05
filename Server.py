from Crypto.Cipher import AES
from Crypto import Random
from PKCS7 import PKCS7

class Server:
    __plain = '''We knew the world would not be the same. A few people laughed, a few people cried, most people were silent.
I remembered the line from the Hindu scripture, the Bhagavad-Gita. Vishnu is trying to persuade the Prince that he should do his duty and to impress him takes on his multi-armed form and says, "Now, I am become Death, the destroyer of worlds."
I suppose we all thought that one way or another.'''

    def __init__(self):
        self._key = Random.new().read(AES.block_size)
        #self._iv  = Random.new().read(AES.block_size)
        self._iv  = "\x00" * AES.block_size
        print "Server initialized:"
        print "Key\t: %s" % self._key.encode('hex')
        print "IV\t: %s" % self._iv.encode('hex')

    def __encrypt(self, message):
        cipher = AES.new(key=self._key, mode=AES.MODE_CBC, IV=self._iv)
        pmessage = PKCS7.pad(message)
        return cipher.encrypt(pmessage)

    def __decrypt(self, ct):
        cipher = AES.new(key=self._key, mode=AES.MODE_CBC, IV=self._iv)
        pmessage = cipher.decrypt(ct)
        message  = PKCS7.unpad(pmessage)
        return message

    def hello(self):
        return self.__encrypt(self.__plain)

    def process(self, message):
        return self.__decrypt(message)
