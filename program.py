from Server import Server
from POA import POA

def oracle(message):
    try:
        server.process(message)
        return True
    except:
        return False

server = Server()
ct = server.hello()
poa = POA()
poa.attack_aes128_pkcs7(ct, oracle)

