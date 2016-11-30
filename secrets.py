import os
from Crypto.PublicKey import RSA
from Crypto import Random
from Crypto.Cipher import PKCS1_OAEP


def generate_keys(use_ssh=False):
    '''
    Generate public/private keys. If use_ssh is true it uses the
    .ssh directory so that the keys can double as SSH keys.
    '''
    random_generator = Random.new().read
    key = RSA.generate(2048, random_generator)
    os.mkdir('/usr/.secrets')
    with open(os.path.join(os.path.expanduser("~"),
                           ".secrets/private.key"), 'w') as content_file:
        os.chmod(os.path.join(os.path.expanduser("~"),
                              ".secrets/private.key"), 0600)
        content_file.write(key.exportKey('PEM'))
    pubkey = key.publickey()
    with open(os.path.join(os.path.expanduser("~"),
                           ".secrets/public.key"), 'w') as content_file:
        content_file.write(pubkey.exportKey('OpenSSH'))


def encrypt(message, yourkey):
    '''
    Encrypt a message using public key yourkey.
    '''
    key = RSA.importKey(yourkey)
    cipher = PKCS1_OAEP.new(key)
    ciphertext = cipher.encrypt(message)
    return ciphertext


def decrypt(ciphertext, mykey):
    '''
    Decrypt a message in ciphertext using private key mykey.
    '''
    key = RSA.importKey(mykey)
    cipher = PKCS1_OAEP.new(key)
    message = cipher.decrypt(ciphertext)
    return message


if __name__ == "__main__":
    pubkey = file(os.path.join(os.path.expanduser("~"), ".ssh/id_rsa.pub")).read()
    key = file(os.path.join(os.path.expanduser("~"), ".ssh/id_rsa")).read()
    message = "Hello world"
    ct = encrypt(message, pubkey)
    print("encrypted: "+ct)
    print("decrypted: "+decrypt(ct, key))
