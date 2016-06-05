class PKCS7:
	@staticmethod
	def pad(message, blocksize=16):
		m = len(message) % blocksize
		if (m==0):
			p = blocksize
		else:
			p = blocksize - m
		return message + (chr(p) *p)

	@staticmethod
	def unpad(message, blocksize=16):
		l  = len(message)
		lb = message[-1]
		p  = ord(lb)
		if (p <= blocksize and p > 0 and p<=l):
			if ((chr(p) *p) == (message[(l-p):])):
				return message[:(l-p)]
		raise TypeError("Incorrect padding")