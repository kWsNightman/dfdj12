"""
Core Auth54 module to store all ecdsa auth methods.
"""
from fastecdsa import curve
from fastecdsa import ecdsa as fast_ecdsa
from fastecdsa import keys
from fastecdsa.encoding.der import DEREncoder


def sign_data(priv_key, data):
    """
    Sign passed data with private key using
    fast_ecdsa library.
    """
    r, s = fast_ecdsa.sign(
        data.encode(), int(priv_key, 16), curve=curve.secp256k1)
    sign = bytes.hex(DEREncoder.encode_signature(r, s))
    return sign


def verify_signature(pub_key, signature, data):
    """
    Verify created for data signature with user
    public key.
    """
    r, s = DEREncoder.decode_signature(bytes.fromhex(signature))
    try:
        x, y = int(pub_key[2:66], 16), int(pub_key[66:], 16)
    except ValueError:
        return False

    valid = fast_ecdsa.verify(
        (r, s), data.encode(), (x, y), curve=curve.secp256k1)
    return valid


def generate_key_pair():
    """
    Generates key pair of ecdsa keys in hex with fastecdsa lib.
    :return: private_key, public_key
    """
    private_key, public_key = keys.gen_keypair(curve=curve.secp256k1)
    # Converts public key from int in hex
    private_key = format(private_key, '064x')
    # Converts public_key coordinates X and Y in hex, concat it and add
    # prefix 04. That prefix means that we have pair of coordinates.
    public_key = '04' + format(public_key.x, '064x') + \
                 format(public_key.y, '064x')
    return private_key, public_key
