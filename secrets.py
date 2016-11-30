import os
from Crypto.PublicKey import RSA
from Crypto import Random
from Crypto.Cipher import PKCS1_OAEP


def generate_keys(save_keys=False, use_ssh=False, location=None):
    '''
    Generate public/private keys. If `use_ssh` is true it uses the
    ~/.ssh directory so that the keys can double as SSH keys. If `location`
    is provided it uses that. Returns dict containing keys.
    '''

    LOCATION = ".secrets"
    if use_ssh and location:
        print("Don't use both of `use_ssh` and `location` together.")
        assert(False)
    if use_ssh:
        LOCATION = ".ssh"
    elif save_keys:
        os.mkdir(os.path.join(os.path.expanduser("~"), '.secrets'))

    random_generator = Random.new().read
    key = RSA.generate(2048, random_generator)
    private = key.exportKey('PEM')
    pubkey = key.publickey()
    public = pubkey.exportKey('OpenSSH')

    if save_keys:
        with open(os.path.join(os.path.expanduser("~"),
                               LOCATION,
                               "id_rsa"), 'w') as content_file:
            os.chmod(os.path.join(os.path.expanduser("~"),
                                  LOCATION,
                                  "id_rsa"), "0600")
            content_file.write(private)
        with open(os.path.join(os.path.expanduser("~"),
                               LOCATION,
                               "id_rsa.pub"), 'w') as content_file:
            content_file.write(public)

    return {"private": private, "public": public}

def encrypt(message, yourkey):
    '''
    Encrypt a message using public key `yourkey`.
    '''
    key = RSA.importKey(yourkey)
    cipher = PKCS1_OAEP.new(key)
    ciphertext = cipher.encrypt(message)
    return ciphertext


def decrypt(ciphertext, mykey):
    '''
    Decrypt a message in ciphertext using private key `mykey`.
    '''
    key = RSA.importKey(mykey)
    cipher = PKCS1_OAEP.new(key)
    message = cipher.decrypt(ciphertext)
    return message


if __name__ == "__main__":
    pubkey = open(os.path.join(os.path.expanduser("~"),
                               ".ssh/id_rsa.pub")).read()
    key = open(os.path.join(os.path.expanduser("~"),
                            ".ssh/id_rsa")).read()
    message = "Hello world"
    ct = encrypt(message.encode('utf8'), pubkey)
    print("encrypted: " + str(ct))
    print("decrypted: " + decrypt(ct, key))
    generate_keys()
