import logging

from POA import POA
from Server import Server

LOGLEVEL = logging.DEBUG

def oracle(message):
    try:
        server.process(message)
        return True
    except:
        return False

def setup_log():
    #Root logger
    logger = logging.getLogger()
    logger.setLevel(LOGLEVEL)
    ch = logging.StreamHandler()
    ch.setFormatter(logging.Formatter('[%(name)s] - %(levelname)s - %(message)s'))
    logger.addHandler(ch)

setup_log()
server = Server()
ct = server.hello()
poa = POA()
poa.attack_aes128_pkcs7(ct, oracle)

