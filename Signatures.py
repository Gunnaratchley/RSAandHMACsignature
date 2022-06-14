import base64
import timeit
import numpy as np
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from Crypto.Hash import HMAC, SHA256

def hmac_encryptyion(message):
    m_byte = bytes(message, "utf-8")
    
    k = get_random_bytes(16)
    file_out = open ("hmackey.txt", "wb")
    file_out.write(k)
    file_out.close()
    hash_message = HMAC.new(k, digestmod=SHA256)
    hash_message.update(m_byte)
    digest = hash_message.hexdigest()
    print(digest)

    file_out = open("mactext.txt", "w")
    file_out.write('{0}{1}'.format(message, digest))
    file_out.close()

def hmac_verification(file):
    file_in = open(file, 'r')
    message = file_in.read(18)
    message_bytes = bytes(message, "utf-8")
    print(message)

    hr = file_in.read()
    hr_bytes = bytes(hr, "utf-8")
    print(hr)
    file_in.close()

    file_in = open("hmackey.txt", "rb")
    k = file_in.read()
    file_in.close()

    hash_message = HMAC.new(k, message_bytes, digestmod=SHA256)
    # if hash_message.hexverify(hr):
    #     print("The message is a match")
    # else:
    #     print("something went wrong")
    try:
        hash_message.hexverify(hr_bytes)
        print("The message is a match")
    except ValueError:
        print("The message or key is wrong")

def rsa_key_generation():
    #Key generation and file generation
    RSA_key = RSA.generate(2048)
    private_key = RSA_key.export_key()
    file_out = open("private.txt", "wb")
    file_out.write(private_key)
    file_out.close()
    #Publick key generation and file creation to share
    public_key = RSA_key.publickey().export_key()
    file_out = open("public_key.txt", "wb")
    file_out.write(public_key)
    file_out.close()

def rsa_signature(message):
    message_byte = bytes(message, 'utf-8')

    key = RSA.import_key(open('private.txt').read())
    hash_message = SHA256.new(message_byte)
    signature = pkcs1_15.new(key).sign(hash_message)
    print(signature)

    file_out = open("sigtext.txt", "w")
    file_out.write('{0}{1}'.format(message, signature))
    file_out.close()

def rsa_verification(file):
    
    file_in = open(file, 'r')
    message = file_in.read(18)
    message_byte = bytes(message, "utf-8")

    signature = file_in.read()
    sig_to_bytes = bytes(signature, "utf-8")
    print(signature)
    file_in.close()
    
    priv_key = RSA.import_key(open('private.txt').read())
    key = RSA.import_key(open('public_key.txt').read())
    hash_message = SHA256.new(message_byte)
    rsa_signature = pkcs1_15.new(priv_key).sign(hash_message)
    if (pkcs1_15.new(key).verify(hash_message, rsa_signature)):
        print("The signature is valid.")
    try:
        pkcs1_15.new(key).verify(hash_message, rsa_signature)
        print("The signature is valid.")
    except (ValueError, TypeError):
        print("The signature is invalid")

def hmac_gen():
    message = input("User-input message for HMAC Generation: ")
    message_byte = bytes(message, 'utf-8')
    key = get_random_bytes(16)

    hash_message = HMAC.new(key, digestmod = SHA256)
    hmac_repetitions = (timeit.timeit('hash_message.update(message_byte)',\
        globals = {'hash_message' : hash_message, 'message_byte' : message_byte}, number = 100))

    average_hmac = np.mean(hmac_repetitions)
    print(average_hmac)

def signature():
    #Key generation needed for hash
    rsa_key_generation()
    message = input("User-imput message for RSA Digital Signature: ")
    message_byte = bytes(message, 'utf-8')
    key = RSA.import_key(open('private.txt').read())
    hash_message = SHA256.new(message_byte)

    #Average of 100 repetitions of signature generation
    signature_generation_reps = (timeit.timeit('signature = pkcs1_15.new(key).sign(hash_message)',\
        globals = {'signature' : signature, 'pkcs1_15':pkcs1_15,'key':key,'hash_message':hash_message}, number = 100))
    average_signature_generation = np.mean(signature_generation_reps)

    #Average of 100 repitions of RSA signature verification
    rsa_signature = pkcs1_15.new(key).sign(hash_message)
    rsa_signature_ver = (timeit.timeit('pkcs1_15.new(key).verify(hash_message, rsa_signature)',\
        globals={'pkcs1_15':pkcs1_15,'key':key,'hash_message':hash_message,'rsa_signature':rsa_signature},number = 100))
    average_signature_verification = np.mean(rsa_signature_ver)

    print("Average Signature generation time: ", average_signature_generation)
    print("Average Signature verification time: ", average_signature_verification)


message = input("Please enter message for HMAC Verification: ")
hmac_encryptyion(message)
hmac_verification("mactext.txt")
rsa_message = input("Please enter message for RSA signature: ")
rsa_key_generation()
rsa_signature(rsa_message)
rsa_verification("sigtext.txt")

hmac_gen()
signature()