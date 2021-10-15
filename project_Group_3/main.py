from Cryptodome.PublicKey import ElGamal
from Cryptodome import Random
from ofb import *
from signature import *
from serpent import bitstring2hexstring, hex2string


def keysgenerator():  # generate a public and private key
    keys = ElGamal.generate(256, Random.new().read)
    return keys


def calc_common_key(p, Xa, Yb):  # get the other party public key and calc common key:
    commonkey = pow(Yb, Xa, p)  # K=((g^xb)^Xa)mod p=(g^XaXb)mod p
    return commonkey


def make_a_message_and_signature_to_transmit(keys, Yb):
    Message = 'we are group 3 and this  is the message'
    plainText = makptright(Message)

    p = int(keys.p)
    Xa = int(keys.x)
    g = int(keys.g)
    commonkey = calc_common_key(p, Xa, Yb)
    hexkcommnkey = hex(commonkey)
    iv, Ctext = ofbEnc(plainText, hexkcommnkey)
    s1, s2 = signing(plainText, g, Xa, p)  # making a signature
    print("initializing vector(iv):", iv, "\nencryptedMsg(Ctext):", Ctext,
          "\nSignature(s1,s2):\nS1:", s1, "\nS2:", s2)
    # to_send[Signature(s1,s2),encryptedMsg(Ctext),initializing vector(iv)]
    return iv, Ctext, s1, s2, hexkcommnkey


def on_Message_Ricevere(keys, iv, Ctext, s1, s2, Yb, hexkcommnkey):
    # check if the signature is valid
    plain = ofbDec(Ctext, hexkcommnkey, iv)
    ints = list(plain)
    l = convert(ints)
    hextlalalaext = bitstring2hexstring(l)
    strplaintext = hex2string(hextlalalaext)  # decrypt the message ot calc the hash
    g = int(keys.g)
    p = int(keys.p)
    ValidSignature = verification(strplaintext, Yb, s1, s2, g, p)
    print("This Signature is Valid") if ValidSignature else print("This Signature is NOT Valid")
    if(ValidSignature):
        print ("the message after dcryption is :" ,strplaintext)


def main():
    Yb = 37250134217189821209954084407989998456896241785557502923320401706159181025613  # public key for the other party
    # this is for the example
    keys = keysgenerator()
    iv, Ctext, s1, s2, hexkcommnkey = make_a_message_and_signature_to_transmit(keys, Yb)
    on_Message_Ricevere(keys, iv, Ctext, s1, s2, int(keys.y), hexkcommnkey)


main()
