import os
import json
import shutil
import random
from hashlib import sha256
from tqdm import tqdm

users = {}
current_user = None
users_db = 'users.json'

def writeUsersFile():
    with open(users_db, 'w') as file:
        json.dump(users, file)

def readUsersFile():
    global users
    if users_db in os.listdir():
        with open(users_db, 'r') as file:
            users = json.load(file)
    for user in users:
        create_inbox(user)


def logIn():
    global current_user
    print("--Logging in to Secure Messaging System--")
    u = getUserName()
    if u not in users:
        print("User not registered")
        userRegistration(u)
        logIn()
        return
    p = getPassword()
    hash = sha256()
    hash.update(p.encode('utf-8'))
    hashed_password = hash.hexdigest()
    if users[u]['password'] == hashed_password:
        print("Login successful")
        current_user = u
        showMenu()
    else:
        print("Invalid password")
        print('got', hashed_password, 'expected', users[u]['password'])
        logIn()


def showMenu():
    print("--Secure Messaging System--")
    print("Logged in as", current_user)
    print("1. User Registration and Key Generation")
    print("2. File Compression")
    print("3. File Decompression")
    print("4. File Encryption")
    print("5. File Transfer")
    print("6. File Decryption")
    print("7. Switch User")
    print("8. Show Detailed Menu")
    print("9. Exit")
    choice = input("Enter your choice: ")
    if "1" in choice:
        userRegistration()
    elif "2" in choice:
        fileCompression()
    elif "3" in choice:
        fileDecompression()
    elif "4" in choice:
        fileEncryption()
    elif "5" in choice:
        success = fileTransfer()
        if not success:
            print("File transfer failed")
        else:
            print("File transfer successful")
        
    elif "6" in choice:
        fileDecryption()
    elif "7" in choice:
        logIn()
    elif "8" in choice:
        showDetailedMenu()
    elif "9" in choice:
        exit()
    else:
        print("Invalid choice")
    showMenu()

def showDetailedMenu():
    print("--Secure Messaging System--")
    print("Logged in as", current_user)
    print("1. User Registration and Key Generation -- Generate public and private keys for a new user")
    print("2. File Compression -- Compress a file into .zip format")
    print("3. File Decompression -- Decompress a .zip file")
    print("4. File Encryption -- Encrypt a file using your own public key")
    print("5. File Transfer -- Encrypt using the destination user's public key and send it to them")
    print("6. File Decryption -- Decrypt a file using your own private key")
    print("7. Switch User -- Log in as a different user")
    print("8. Show Detailed Menu")
    print("9. Exit")
    choice = input("Enter your choice: ")
    if "1" in choice:
        userRegistration()
    elif "2" in choice:
        fileCompression()
    elif "3" in choice:
        fileDecompression()
    elif "4" in choice:
        fileEncryption()
    elif "5" in choice:
        success = fileTransfer()
        if not success:
            print("File transfer failed")
        else:
            print("File transfer successful")
        
    elif "6" in choice:
        fileDecryption()
    elif "7" in choice:
        logIn()
    elif "8" in choice:
        showDetailedMenu()
    elif "9" in choice:
        exit()
    else:
        print("Invalid choice")
    showMenu()

def userRegistration(u = None):
    print("--User Registration and Key Generation--")
    if u == None:
        u = getUserName()
    if u not in users:
        users[u] = {'public_key': '', 'private_key': '', 'password': ''}
        p = getPassword()
        hash = sha256()
        hash.update(p.encode('utf-8'))
        hashed_password = hash.hexdigest()
        users[u]['password'] = hashed_password
        pub, priv = genKeyPair()
        users[u]['public_key'] = pub
        users[u]['private_key'] = priv
        writeUsersFile()
        print(f"User {u} registered successfully")
    else:
        print("User already registered")
    create_inbox(u)

def genKeyPair():
    print("Generating key pair")
    p = getLargePrime()
    q = getLargePrime()
    n = p * q
    phi = (p - 1) * (q - 1)
    e = 13
    d = multiplicative_inverse(e, phi)
    return ((e, n), (d, p, q))


def gcd(a, b):
    while b != 0:
        a, b = b, a % b
    return a

def multiplicative_inverse(e, phi):
    """euclids extended algorithm"""
    u0, u1 = 0, 1
    a, b = e, phi

    while a != 0:
        q = b // a
        r = b % a
        u0, u1 = u1, u0 - q * u1
        a, b = r, a

    if b == 1:
        return u0 % phi

    return None

def getLargePrime():
    while True:
        num = random.randrange(1000, 9999)
        if isPrime(num):
            return num
        
def isPrime(n):
    for i in range(2,int(n**0.5)+1):
        if n%i==0:
            return False
        
    return True
    
def encryptFile(f, d_pub_key):
    # RSA encryption
    e, n = d_pub_key
    with open(f, 'r') as file:
        with open(f + '.enc', 'w') as enc_file:
            enc_text = ''
            for ch in file.read():
                m = ord(ch)
                c = m**e % n
                enc_text += str(c) + ' '
            enc_file.write(enc_text)
    return f + '.enc'

def decryptFile(f, key):
    # RSA decryption
    d, p, q = key
    n = p * q
    with open(f, 'r') as file:
        with open(f + '.dec', 'w') as dec_file:
            dec_text = ''
            for ch in tqdm(file.read().split(' ')):
                try:
                    c = int(ch)
                except:
                    continue
                m0 = c**d
                m = m0 % n
                dec_text += chr(m)

            dec_file.write(dec_text)
    return f + '.dec'


def fileCompression():
    print("--File Compression--")
    f = getDirectoryName()
    shutil.make_archive(f, 'zip', f)
    print("File compressed successfully as " + f + '.zip')

def fileDecompression():
    print("--File Decompression--")
    f = getDirectoryName()
    shutil.unpack_archive(f, f)
    print("File decompressed successfully")

def fileEncryption():
    print("--File Encryption--")
    f = getFileName()
    key = users[current_user]['public_key']
    enc = encryptFile(f, key)
    print("File encrypted successfully as " + enc)
    
def fileDecryption():
    print("--File Decryption--")
    print(f"{current_user}'s inbox: ")
    inbox = os.listdir(f"{current_user}_inbox")
    print(inbox)
    f = f"{current_user}_inbox/" + getFileName()  
    key = users[current_user]['private_key']
    dec = decryptFile(f, key)
    print("File decrypted successfully as " + dec)

def fileTransfer():
    print("--File Transfer--")
    f = getFileName()
    print("Logged in as: ", current_user)
    print("Available Users: ", list(users.keys()))
    d = getDestinationUser()
    count = 0
    if d not in users:
        print("User not registered")
        if count > 3:
            print("Maximum attempts exceeded")
            return False
        d = getDestinationUser()
        count += 1
    d_pub_key = users[d]['public_key']
    enc = encryptFile(f, d_pub_key)
    sendFile(enc, d)
    return True

def getUserName():
    u = input("Enter username: ")
    if len(u) > 0:
        return u.lower()
    else:
        print("Invalid username")
        getUserName()


def getPassword():
    p = input("Enter password: ")
    if len(p) > 0:
        return p
    else:
        print("Invalid password")
        getPassword()


def getFileName():
    return input("Enter file name: ")


def getDirectoryName():
    return input("Enter directory name: ")


def getDestinationUser():
    d = input("Enter destination user: ")
    if len(d) > 0:
        return d
    else:
        print("Invalid destination user")
        getDestinationUser()


def create_inbox(u):
    if f"{u}_inbox" not in os.listdir():
        os.mkdir(f"{u}_inbox")


def sendFile(f, d):
    shutil.copy(f, f"{d}_inbox/{f}")


if __name__ == "__main__":
    readUsersFile()
    logIn()
    showMenu()
