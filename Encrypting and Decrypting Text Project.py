#!/usr/bin/env python
# coding: utf-8

# In[ ]:


import random


class Transposition:

    def __init__(self, word):
        self.word = word

    def scramble(self):
        # shuffle the characters in the word using random.sample
        return ''.join(random.sample(self.word, len(self.word)))
        # scramble the letters in the word


# Substitution_Polyalphabetic_Vigenere
class Substitution:  # CHILD CLASS OF MESSAGE CLASS
    def __init__(self, plainText, keyword="BIRD"):
        self.plainText = plainText
        self.keyword = keyword

        # as all string input will have to be formatted, this will also be a main class method
    def formatPlainText(self, plainText):
        # remove spaces and change into list format for iteration
        self.plainText = list(self.plainText.replace(" ", ""))
        return self.plainText

    # this method will go into the main class (MessageClass)
    # (because you have to check that each input is valid before passing it to encryption)
    def checkString(self, plainText):
        strValid = False

        # iterate through the formatted text
        for i in self.formatPlainText(plainText):

            # since we're only working with uppercase letters,
            # check that the unicodes are within range (A to Z)
            if ord(i) < 65 or ord(i) > 90:
                return strValid
        strValid = True

        return strValid

    def generateKey(self, plainText, keyword):

        key = list(self.keyword)
        if len(self.plainText) != len(keyword):

            # if the two are not the same length, need to wrap around...
            # the keyword to make up for the extra letters in the plaintext
            for i in range(len(self.plainText) - len(keyword)):
                key.append(key[i % len(key)])
        else:
            return key
        return key

    # Vigenere Encryption = (Plaintext + Key) mod 26
    def encryption(self, plainText, key):

        encrypted = []

        # first need to add the unicodes of each letter at the current index
        # then, find the remainder when divided by 26
        for i in range(len(self.plainText)):
            sumUnicodes = (ord(self.plainText[i]) + ord(key[i])) % 26

            # need to add the lowest value to the sum
            sumUnicodes += 65
            encrypted.append(chr(sumUnicodes))

        return encrypted

    # Vigenere Decryption = (Encryption - Key + 26) mod 26
    def decryption(self, encryptMsg, key):

        decrypted = []

        # opposite of encryption, and iterating through the encrypted message
        for i in range(len(encryptMsg)):
            sumUnicodes = (ord(encryptMsg[i]) - ord(key[i]) + 26) % 26
            sumUnicodes += 65
            decrypted.append(chr(sumUnicodes))

        return decrypted




# CaesarCipher class
class CaesarCipher:
    # initialization method that sets instance variables for shift
    def __init__(self, shift):
        self.shift = shift

    # encrypt method
    def encrypt(self, plaintext):
        # Empty string ciphertext to hold the encrypted message
        ciphertext = ""
        # Iterate over each character in the plaintext
        for char in plaintext:
            # Check if character is an alphabetic character using the isalpha() method
            if char.isalpha():
                # Determine if the character is uppercase or lowercase
                if char.isupper():
                    # Encrypt uppercase characters
                    ciphertext += chr((ord(char) + self.shift - 65) % 26 + 65)
                else:
                    # Encrypt lowercase characters
                    ciphertext += chr((ord(char) + self.shift - 97) % 26 + 97)
            else:
                # Encrypted character is appended to ciphertext
                ciphertext += char
        # return ciphertext once the all characters have been encrypted
        return ciphertext

    def decrypt(self, ciphertext):
        # Empty string plaintext to hold the plaintext message
        plaintext = ""
        # Iterate over each character in the ciphertext
        for char in ciphertext:
            # Check if character is an alphabetic character using the isalpha() method
            if char.isalpha():
                # Determine if the character is uppercase or lowercase
                if char.isupper():
                    # Decrypt uppercase characters
                    plaintext += chr((ord(char) - self.shift - 65) % 26 + 65)
                else:
                    # Decrypt lowercase characters
                    plaintext += chr((ord(char) - self.shift - 97) % 26 + 97)
            else:
                # plaintext character is appended to plaintext
                plaintext += char
        # return plaintext once the all characters have been decrypted
        return plaintext


import math

# list of prime numbers
prime_num_list = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97,
                  101, 103, 107, 109, 113, 127, 131, 137, 139, 149, 151, 157, 163, 167, 173, 179, 181, 191, 193, 197,
                  199]


# RSA Encryption class
class RSA_Encryption:

    # initialization method that sets instance variables for "p", "q", "n", "phi", "e", "d", and "n"
    def __init__(self, p, q):
        self.p = p
        self.q = q
        self.n = p * q
        self.phi = (p - 1) * (q - 1)
        self.e = self.generate_public_key()
        self.d = self.generate_private_key()

    # generate_public_key method
    def generate_public_key(self):
        # Generates a random integer e between 2 and phi - 1, where phi is the Euler totient function of n
        e = random.randint(2, self.phi - 1)
        # start a loop that continues until e and phi are co-prime (the GCD of e and phi is 1)
        while math.gcd(e, self.phi) != 1:
            # If e and phi are not co-prime, a new random integer is generated for e until a suitable value is found
            e = random.randint(2, self.phi - 1)
            # return e (public key) once a suitable value for e is found
        return e

    # generate_private_key method
    def generate_private_key(self):
        # Computes the private key d using the formula d = e^(-1) mod phi(n). Finding the modular inverse
        d = pow(self.e, -1, self.phi)
        # return d (private key)
        return d

    # encrypt method
    def encrypt(self, plaintext):
        # Convert each character to its corresponding Unicode code point
        code_points = [ord(c) for c in plaintext]
        # Encrypt each code point using the public key
        encrypted_points = [pow(c, self.e, self.n) for c in code_points]
        # Convert each encrypted code point to a string
        encrypted_chars = [str(c) for c in encrypted_points]
        # Join the encrypted code points into a single string
        encrypted_message = " ".join(encrypted_chars)
        return encrypted_message

    # decrypt method
    def decrypt(self, ciphertext):
        # Split the encrypted message into encrypted code points
        encrypted_chars = ciphertext.split(" ")
        # Convert each encrypted code point to an integer
        encrypted_points = [int(c) for c in encrypted_chars]
        # Decrypt each encrypted code point using the private key
        decrypted_points = [pow(c, self.d, self.n) for c in encrypted_points]
        # Convert each decrypted code point to a character
        decrypted_chars = [chr(c) for c in decrypted_points]
        # Join the decrypted characters into a single string
        decrypted_message = "".join(decrypted_chars)
        return decrypted_message


class Message:
    def __init__(self, message):
        self.message = message

    def get_message(self):
        return self.message

    def random_cipher(self):
        cipher = [CaesarCipher, RSA_Encryption, Substitution, Transposition]
        choose_cipher = random.choice(cipher)
        return choose_cipher


def message():
    List = []
    while True:
        p = random.choice(prime_num_list)
        q = random.choice(prime_num_list)
        x = CaesarCipher(3)
        y = RSA_Encryption(p, q)
        try:
            plaintext = str(input("Enter a Message: "))
            if plaintext == 'stop':
                print("")
                for i in List:
                    print(i)
                break
        except ValueError:
            print("Error: Invalid input")
            continue
        message = Message(plaintext)
        w = message.random_cipher()
        if w == CaesarCipher:
            ciphertext = x.encrypt(plaintext)
            decrypted_text = x.decrypt(ciphertext)
            ceasar1 = f'\nOriginal Message: "{plaintext}"\n'                       f'Ciphertext: "{ciphertext}"\n'                       f'Decrypted Message: "{decrypted_text}"\n'                       f'Encryption Method: "Caesar Cipher"\n'
            List.append(ceasar1)

        elif w == RSA_Encryption:
            ciphertext = y.encrypt(plaintext)
            decrypted_text = y.decrypt(ciphertext)
            RSA1 = f'\nPlaintext: "{plaintext}"\n'                    f'Ciphertext: "{ciphertext}"\n'                    f'Decrypted message: "{decrypted_text}"\n'                    f'Encryption Method: "RSA"\n'
            List.append(RSA1)

        elif w == Substitution:
            keyword = "MOUSE"
            word = Substitution(plaintext, keyword)
            key = word.generateKey(plaintext, keyword)
            encryptMsg = word.encryption(plaintext, key)
            decryptMsg = word.decryption(encryptMsg, key)
            substitution1 = f'\nPlaintext: "{plaintext}"\n'                             f'Ciphertext: "{("".join(encryptMsg))}"\n'                             f'Decrypted message:", "{("".join(decryptMsg))}"\n'                             f'Encryption Method: "Substitution"\n'
            List.append(substitution1)

        elif w == Transposition:
            transCipher = Transposition(plaintext)
            Transposition1 = f'\nOriginal Message: "{plaintext}"\n'                              f'Ciphertext: "{transCipher.scramble()}"\n'                              f'Encryption Method: "Transposition"\n'
            List.append(Transposition1)
message()

#TGIS

