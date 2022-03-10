import LWE.standard.LWE_PKE as LWE_PKE
import LWE.ring.FHE_PKE as FHE_PKE

"""
Name
----
CLI

Description
-----------
This module implements a singleton instance of a command-line intergace
for an LWE public key encryption. It models how to use the LWE_PKE module
Because of this, note that many parameters are fixed. Interact with the module
directly to use custom parameters.

Contents
--------
CLI : runs a command-line interface of LWE
"""

def help_com():
    print("""
DESCRIPTION
***********

    The command line maintains customisable variables x, y, and z.
    It also maintains two objects alice and bob who represent two LWE encryption instances
    This command line allows interaction with these variables and instances such as encryption,
    decryption and adding/multiplication (for Homomorphic encryption only).
    When the command line starts it will ask for an encryption mode:
        [A] = amortised LWE public key cryptography system
        [L] = standard (single-bit) LWE public key cryptography
        [R] = fully homomorphic ring-LWE system

SYNTAX
******

    Only the first letter of commands and variable names are read, allowing shortening.
    For example 'encrypt alice x 10110101' may be shortened to 'e a x 10110101'

    [source] = can be replaced with x, y, or z
        the variable(s) used in the command

    [destination] = can be replaced with x, y, or z
        where the commands output is stored
        
    [instance] = can be replace with alice, or bob
        the LWE instance used in the command
        
    [message] = a bitstring (when in LWE mode)
              = a comma delimited string of numbers representing a polynomial where the
                first number is the highest order coefficient (when in Ring-LWE mode)
        the message that is used for encryption
    
COMMANDS
********

    help -
        Displays the help page

    encrypt [instance] [source] [message] -
        Encrypts [message] using the specified [instance] and stores the ciphertext in [source] variable.
        This automatically uses the opposing instance's public key to encrypt with.
    
    decrypt [instance] [source] -
        Decrypts the ciphertext in [source] using the secret key of [instance]. The output is printed
        to the terminal.
        
    print [source] -
        Prints the ciphertext in the [source] variable to the terminal.
    
    print [instance] -
        Prints the public key of [instance] to the terminal.
        
    add [source] [source] [destination] - 
        Adds the ciphertexts in the two [source] variables and stores the result in [destination]
        Only defined for Homoorphic modes
    
    multiply [source] [source] [destination] - 
        Multiplies the ciphertexts in the two [source] variables and stores the result in [destination]
        Only defined for Homoorphic modes

""")
    
help_com()
    
class CommandError(Exception): pass

def CLI():
    """
        A basic CLI for interacted with the (R)LWE systems.
    """
    val = None
    while val not in ['r', 'a', 'l']:
        print("Type (H) for help")
        choice = input("Choose mode FHE-RLWE (R), LWE (A) or single-bit LWE (L)\n/: ").split()
        val = choice[0].lower()[0]
        prefix = val.upper()+"/: "
        if (val=="h"):
            help_com()
            CLI()
        elif (val=="r"):
            pt_c = int(input("Please enter the plaintext coefficient for Alice\n"+prefix))
            print("creating...")
            alice = FHE_RLWE.createFHE(pt_coeff=pt_c)

            pt_c = int(input("Please enter the plaintext coefficient for Bob\n"+prefix))
            print("creating...")
            bob = FHE_RLWE.createFHE(pt_coeff=pt_c)

        elif (val=="a"):
            pt_n = int(input("Please enter the plaintext length for Alice"+prefix))
            print("creating...")
            alice = LWE_PKE.createLWE(mb=True, l=pt_n, n=128)

            pt_n = int(input("Please enter the plaintext length for Bob"+prefix))
            print("creating...")
            bob = LWE_PKE.createLWE(mb=True, l=pt_n, n=128)

        elif (val=="l"):
            print("creating...")
            alice = LWE_PKE.createLWE(mb=False, n=128)
            bob = LWE_PKE.createLWE(mb=False, n=128)

    x, y, z, keyword = None, None, None, None
    while keyword!="q":
        print("Type (H) for help")
        command = input(prefix).lower().split()
        
        keyword = command[0][0]
        
        if (keyword=="h"):
            help_com()
        elif (keyword=="e"): #encrypt
            if ',' in command[3]:
                plain = [int(i) for i in command[3].split(',')]
                print(plain)
            else: plain = command[3]
            if command[1][0]=="a": val = alice.encrypt(plain, bob.getPublicKey())
            elif command[1][0]=="b": val = bob.encrypt(plain, alice.getPublicKey())
            else: print("unknown encryption instance")
                
            if command[2][0]=="x": x = val
            elif command[2][0]=="y": y = val
            elif command[2][0]=="z": z = val
            else: print("unknown destination variable")
        elif (keyword=="d"): #decrypt
            if command[2][0]=="x": val = x
            elif command[2][0]=="y": val = y
            elif command[2][0]=="z": val = z
            else: print("unknown source variable")
            
            if command[1][0]=="a": print(alice.decrypt(val))
            elif command[1][0]=="b": print(bob.decrypt(val))
            else: print("unknown encryption instance")
        elif (keyword=="p"): #print
            if command[1][0]=="a": print(alice.getPublicKey())
            elif command[1][0]=="b": print(bob.getPublicKey())
            elif command[1][0]=="x": print(x)
            elif command[1][0]=="y": print(y)
            elif command[1][0]=="z": print(z)
            else: print("unknown printable variable")
        elif (keyword=="m" or keyword=="a"): #multiply
            if command[1][0]=="x": left = x
            elif command[1][0]=="y": left = y
            elif command[1][0]=="z": left = z
            else: print("unknown source variable")
                
            if command[2][0]=="x": right = x
            elif command[2][0]=="y": right = y
            elif command[2][0]=="z": right = z
            else: print("unknown source variable")
            
            if (keyword=="m"): val = left*right
            elif (keyword=="a"): val = left+right
            
            if command[3][0]=="x": x = val
            elif command[3][0]=="y": y = val
            elif command[3][0]=="z": z = val
            else: print("unknown destination variable")
        elif keyword!="q": print("unknown command: \'" + ''.join(command) + "\'")
    print("quitting...")


if __name__ == '__main__':
    CLI()