from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
import xxtea
from Crypto.Hash import SHA224, HMAC
from cryptography.hazmat.primitives.asymmetric import utils


# Step 1: Asymmetric Key exchange
# - Both parties create a public and private key pair.
# - Use ECDH to calculate and send shared key to use for symmetric encryption/decryption

# Step 2: Key Derivation
# - Since we need a key for both symmetric encryption and HMAC, we will use a Key Derivation Function (KDF) on the shared key 
# that we got from ECDH to create another key (derived key) to use for HMAC

# Step 3: Symmetric Encryption
# - Sender uses XXTEA to encyrpt their message (using shared key created in step 1)

# Step 4: Symmetric Message Authentication
# - Sender uses HMAC using derived key to add a message authentication code to the ciphertext

# Step 5: Digital signature
# - Sender uses their private key to create a digital signature using ECDSA

# DECRYPTION STEPS:
# The message (an object containing the ciphertext, MAC, and signature) is now ready to be sent to the reciever, who will first 
# - decrypt the signature using the sender's public key to verify.
# - reciever does exact same (same params) KDF on their shared key.
# - use this derived key to calculate MAC of ciphertext
# - verify both MACs match
# - If signature is verified, and the MACs match, you can now use the shared key to
# decrypt the original ciphertext and get the original plaintext.
# TADAH HAZZAH BAM BOOM BRRRA SKYAT 

def calculate_keys(private_key, peer_public_key): 
    # create a shared key based on the private key and the received public key
    shared_key = private_key.exchange(ec.ECDH(), peer_public_key)
    # use hkdf to create a new private key for symmetric encryption (shared_key is too big)
    hkdf1 = HKDF(
        algorithm = hashes.SHA224(),
        length = 16,
        salt = None,
        info = None
    )
    hkdf2 = HKDF(
        algorithm = hashes.SHA224(),
        length = 16,
        salt = None,
        info = None
    )

    encrypt_key = hkdf1.derive(shared_key)
    # and another private key for HMAC
    hash_key = hkdf2.derive(encrypt_key)
    return(encrypt_key, hash_key)

def symmetric_secure_send(hash_key, encrypt_key, plaintext):
    # use xxtea to encrypt the plaintext
    cipher = xxtea.encrypt(plaintext, encrypt_key)
    # prepend the message with a MAC using SHA-224
    hash = HMAC.new(hash_key, digestmod=SHA224)
    return (hash.digest(), cipher)

def sign(message, privatekey):
    # Create ECDSA digital signature for the ciphertext using sender's private key
    hashingFunction = hashes.Hash(hashes.SHA224())
    hashingFunction.update(message)
    hashDigest = hashingFunction.finalize()
    digital_signature = privatekey.sign(hashDigest, ec.ECDSA(utils.Prehashed(hashes.SHA224())))
    return digital_signature


def symmetric_receive(hash_key, encrypt_key, message):
    # use HMAC to verify MAC, throws and error if fails
    hash = HMAC.new(hash_key, digestmod=SHA224)
    try:
        hash.verify(message[0])
        # use xxtea to decrypt ciphertext in same function
        plaintext = xxtea.decrypt(message[1], encrypt_key)
        return plaintext
    except ValueError:
        print("Error: Message cannot be authenticated")

def verify_signature(sender_public_key, signature, message):
    # validate digital signature using sender's public key
    try:
        hashingFunction = hashes.Hash(hashes.SHA224())
        hashingFunction.update(message)
        hashDigest = hashingFunction.finalize()
        sender_public_key.verify(signature, hashDigest, ec.ECDSA(utils.Prehashed(hashes.SHA224())))
    except:
        print("Error: Verification of signature failed.")

# create private/public key pairs using P-192 and sign using ECDSA
#Signature, long term, independent of session 
#Generating key pairs
curve = ec.SECP192R1()
alice_private_key_sign = ec.generate_private_key(curve) #For digital signature
alice_public_key_sign = alice_private_key_sign.public_key()

bob_private_key_sign = ec.generate_private_key(curve)
bob_public_key_sign = bob_private_key_sign.public_key()

# data stored in memory
message = ("", "") #Initialise the message

print("Use ctrl + c to close program")
while True:
    # new session
    done = False
    alice_private_key = ec.generate_private_key(curve) #To generate shared keys for ECDH
    alice_public_key = alice_private_key.public_key()

    bob_private_key = ec.generate_private_key(curve)
    bob_public_key = bob_private_key.public_key()

    alice_signature = sign(alice_public_key.__str__().encode(), alice_private_key_sign)
    bob_signature = sign(bob_public_key.__str__().encode(), bob_private_key_sign)

    # verify public key
    verify_signature(bob_public_key_sign, bob_signature, bob_public_key.__str__().encode()) #Checking the signature is correct
    # shared_keys derived in each session to ensure forward secrecy
    alice_shared_keys = calculate_keys(alice_private_key, bob_public_key)
    encrypt_key = alice_shared_keys[0]
    hash_key = alice_shared_keys[1]

    # verify public key
    verify_signature(alice_public_key_sign, alice_signature, alice_public_key.__str__().encode())
    # shared_keys derived in each session to ensure forward secrecy
    bob_shared_keys = calculate_keys(bob_private_key, alice_public_key)
    encrypt_key = bob_shared_keys[0]
    hash_key = bob_shared_keys[1]

    while not(done):
        selection = input("Choose betwen sender (s) and receiver (r) or exit session(e)\n") #User input
        if (selection == "s"):

            # encrypt, MAC, and sign using above methods
            # data saved in memory; could store in file or send over network in future implementation 
            plain = input("Input plaintext\n")
            message = symmetric_secure_send(hash_key, encrypt_key, plain)

        elif (selection == "r"): #Decypt
            #  data decrypted, and MAC verified using above methods
            print(symmetric_receive(hash_key, encrypt_key, message).decode() + "\n")
        
        elif (selection == "e"):
            # start new session
            done = True
