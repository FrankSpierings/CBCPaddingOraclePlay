class POA:

    def __init__(self):
        self.__debug = False
        self.__blocksize = 16
        self.__oracle_calls = 0

    def __get_blocks(self, message):
        return [message[i: i + self.__blocksize] for i in xrange(0, len(message), self.__blocksize)]

    def __default_iv(self):
        return "\x00" * self.__blocksize

    def attack_aes128_pkcs7(self, ciphertext, oracle, iv=None):
        self.__oracle_calls = 0

        if iv==None:
            iv = self.__default_iv()

        ct_blocks = self.__get_blocks(ciphertext)
        ct_blocks_iv = [iv] + ct_blocks

        result = bytearray()
        for i in xrange(0, len(ct_blocks_iv)-1):
            result.extend(self.__decrypt_block(ct_blocks_iv[i+1], ct_blocks_iv[i], oracle))

        print repr(result)
        print "Calls: %d" % self.__oracle_calls
        return result

    def __decrypt_block(self, ct_block, prev_ct_block, callback_oracle):
        padding_nr = 1
        original_ct_block   = bytearray(ct_block)
        prev_ct_block       = bytearray(prev_ct_block)
        pt_block            = bytearray(['.'] * self.__blocksize)
        custom_ct_block     = bytearray(['\x00'] * self.__blocksize)

        if self.__debug:
            print "Current CT   : %s" % str(ct_block).encode('hex')
            print "Previous CT  : %s" % str(prev_ct_block).encode('hex')
            print "Pad nr       : %d" % (padding_nr)
            print "Custom  CT   : %s" % str(custom_ct_block).encode('hex')
            print "Recovered PT : %s" % str(pt_block).encode('hex')

        for index in xrange(self.__blocksize-1, -1, -1):
            found = False
            for char in [chr(c) for c in xrange(0, 0x100)]:
                custom_ct_block[index] = char
                message  = str(custom_ct_block)
                message += str(original_ct_block)
                self.__oracle_calls += 1
                if callback_oracle(message):
                    found = True
                    pt_block[index] = chr(ord(char) ^ padding_nr ^ prev_ct_block[index])
                    if self.__debug:
                        print "Pad nr       : %d" % (padding_nr)
                        print "Custom  CT   : %s" % str(custom_ct_block).encode('hex')
                        print "Recovered PT : %s - %s" % (str(pt_block).encode('hex'), str(pt_block))
                    #Adjust known padding:
                    # - 0x1
                    # - 0x2 0x2
                    # - 0x3 0x3 0x3
                    padding_nr += 1
                    for i in range(self.__blocksize-1, index-1, -1):
                        custom_ct_block[i] = pt_block[i] ^ prev_ct_block[i] ^ padding_nr
                    break
            if not found:
                raise RuntimeError("No valid padding found. Current padding: %d" % padding_nr)
        return pt_block
