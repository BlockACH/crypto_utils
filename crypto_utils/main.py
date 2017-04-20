import ctypes
import string
import random
import pyelliptic
import json

from binascii import hexlify, unhexlify
from pyelliptic.openssl import OpenSSL

DEFAULT_CURVE = 'secp521r1'
DEFAUL_CIPHERNAME = 'aes-256-cfb'


def random_char():
    return random.SystemRandom().choice(string.ascii_uppercase + string.digits)


def random_string(string_len):
    return ''.join(random_char() for _ in range(string_len))


def encrypt(data, pub_keys, curve=DEFAULT_CURVE, ciphername=DEFAUL_CIPHERNAME):
    """
    Encrpt data with AES first with a random key.
    Later encrypt the key used in AES by pub_keys with ECIES encryption.

    data ---(AES, random_key) ---> encrypt_data
    random_key  ---(ECIES, pub_keys) ---> ecies_keys
    """
    random_key = random_string(32)
    encrypted_data, iv = encrypt_aes(data, random_key, ciphername=ciphername)
    keys = [encrypt_ecies(random_key, pub_key, curve) for pub_key in pub_keys]
    encrypted_data_dict = {
        'encrypted_data': encrypted_data,
        'keys': keys,
        'iv': iv,
    }
    return json.dumps(encrypted_data_dict)


def encrypt_ecies(data, pub_key, curve=DEFAULT_CURVE):
    ecc = pyelliptic.ECC(curve=curve)
    return hexlify(ecc.encrypt(data, pub_key))


def encrypt_aes(data, key, ciphername=DEFAUL_CIPHERNAME):
    iv = pyelliptic.Cipher.gen_IV(ciphername)
    ctx = pyelliptic.Cipher(key, iv, 1, ciphername=ciphername)
    ciphertext = ctx.update(data)
    ciphertext += ctx.final()
    return hexlify(ciphertext), hexlify(iv)


def decrypt_aes(encrypted_data, key, iv, ciphername=DEFAUL_CIPHERNAME):
    ctx = pyelliptic.Cipher(key, iv, 0, ciphername=ciphername)
    return ctx.ciphering(encrypted_data)


def decrypt(encrypted_data_dict, priv_key, curve=DEFAULT_CURVE, ciphername=DEFAUL_CIPHERNAME):
    if type(encrypted_data_dict) == str:
        encrypted_data_dict = json.loads(encrypted_data_dict)
    ecc = create_ecc(priv_key, curve=curve)
    keys = [unhexlify(k) for k in encrypted_data_dict['keys']]
    encrypted_data = unhexlify(encrypted_data_dict['encrypted_data'])
    iv = unhexlify(encrypted_data_dict['iv'])

    aes_key = None
    for key in keys:
        try:
            aes_key = ecc.decrypt(key)
        except RuntimeError:
            pass
        else:
            break

    if aes_key:
        data = decrypt_aes(encrypted_data, aes_key, iv, ciphername=ciphername)
        return data

    raise DecryptionFailedException('not able to decrypt the aes key')


def create_ecc(priv_key, curve=DEFAULT_CURVE):
    # enable both hexilified or unhexlified priv_key input
    try:
        priv_key = unhexlify(priv_key)
    except Exception:
        pass
    pub_key = ecc_priv_to_pub_key(priv_key, curve=curve)
    return pyelliptic.ECC(privkey=priv_key, pubkey=pub_key, curve=curve)


def ecc_priv_to_pub_key(priv_key, curve=DEFAULT_CURVE):
    """Does an EC point multiplication to get public key"""
    k = OpenSSL.EC_KEY_new_by_curve_name(OpenSSL.get_curve(curve))
    priv_key = OpenSSL.BN_bin2bn(priv_key, 32, 0)
    group = OpenSSL.EC_KEY_get0_group(k)
    pub_key = OpenSSL.EC_POINT_new(group)

    OpenSSL.EC_POINT_mul(group, pub_key, priv_key, None, None, None)
    OpenSSL.EC_KEY_set_private_key(k, priv_key)
    OpenSSL.EC_KEY_set_public_key(k, pub_key)

    size = OpenSSL.i2o_ECPublicKey(k, 0)
    mb = ctypes.create_string_buffer(size)
    OpenSSL.i2o_ECPublicKey(k, ctypes.byref(ctypes.pointer(mb)))

    OpenSSL.EC_POINT_free(pub_key)
    OpenSSL.BN_free(priv_key)
    OpenSSL.EC_KEY_free(k)
    return mb.raw


class DecryptionFailedException(Exception):
    """not able to decrypt"""

