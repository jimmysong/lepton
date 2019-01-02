from io import BytesIO
from random import randint
from unittest import TestCase

import hashlib
import hmac

from helper import encode_base58_checksum, encode_bech32_checksum, hash160
from _libsec import ffi, lib


GLOBAL_CTX = ffi.gc(lib.secp256k1_context_create(lib.SECP256K1_CONTEXT_SIGN | lib.SECP256K1_CONTEXT_VERIFY), lib.secp256k1_context_destroy)
P = 2**256 - 2**32 - 977
N = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141


class S256Point:

    def __init__(self, csec=None, usec=None):
        if usec:
            self.usec = usec
            self.csec = None
            sec_cache = usec
        elif csec:
            self.csec = csec
            self.usec = None
            sec_cache = csec
        else:
            raise RuntimeError('need a serialization')
        self.c = ffi.new('secp256k1_pubkey *')
        if not lib.secp256k1_ec_pubkey_parse(GLOBAL_CTX, self.c, sec_cache, len(sec_cache)):
            raise RuntimeError('libsecp256k1 produced error')

    def __eq__(self, other):
        return self.sec() == other.sec()
        
    def __repr__(self):
        return 'S256Point({})'.format(self.sec(compressed=False).hex())

    def __rmul__(self, coefficient):
        coef = coefficient % N
        new_key = ffi.new('secp256k1_pubkey *')
        s = self.sec(compressed=False)
        lib.secp256k1_ec_pubkey_parse(GLOBAL_CTX, new_key, s, len(s))
        lib.secp256k1_ec_pubkey_tweak_mul(GLOBAL_CTX, new_key, coef.to_bytes(32, 'big'))
        serialized = ffi.new('unsigned char [65]')
        output_len = ffi.new('size_t *', 65)
        lib.secp256k1_ec_pubkey_serialize(GLOBAL_CTX, serialized, output_len, new_key, lib.SECP256K1_EC_UNCOMPRESSED)
        return self.__class__(usec=bytes(serialized))

    def __add__(self, scalar):
        '''Multiplies scalar by generator, adds result to current point'''
        coef = scalar % N
        new_key = ffi.new('secp256k1_pubkey *')
        s = self.sec(compressed=False)
        lib.secp256k1_ec_pubkey_parse(GLOBAL_CTX, new_key, s, len(s))
        lib.secp256k1_ec_pubkey_tweak_add(GLOBAL_CTX, new_key, coef.to_bytes(32, 'big'))
        serialized = ffi.new('unsigned char [65]')
        output_len = ffi.new('size_t *', 65)
        lib.secp256k1_ec_pubkey_serialize(GLOBAL_CTX, serialized, output_len, new_key, lib.SECP256K1_EC_UNCOMPRESSED)
        return self.__class__(usec=bytes(serialized))
    
    def verify(self, z, sig):
        msg = z.to_bytes(32, 'big')
        sig_data = sig.cdata()
        return lib.secp256k1_ecdsa_verify(GLOBAL_CTX, sig_data, msg, self.c)

    def sec(self, compressed=True):
        '''returns the binary version of the SEC format'''
        if compressed:
            if not self.csec:
                serialized = ffi.new('unsigned char [33]')
                output_len = ffi.new('size_t *', 33)

                lib.secp256k1_ec_pubkey_serialize(
                    GLOBAL_CTX, serialized, output_len, self.c, lib.SECP256K1_EC_COMPRESSED,
                )
                self.csec = bytes(ffi.buffer(serialized, 33))
            return self.csec
        else:
            if not self.usec:
                serialized = ffi.new('unsigned char [65]')
                output_len = ffi.new('size_t *', 65)

                lib.secp256k1_ec_pubkey_serialize(
                    GLOBAL_CTX, serialized, output_len, self.c, lib.SECP256K1_EC_UNCOMPRESSED,
                )
                self.usec = bytes(ffi.buffer(serialized, 65))
            return self.usec

    def hash160(self, compressed=True):
        return hash160(self.sec(compressed))

    def address(self, compressed=True, testnet=False):
        '''Returns the address string'''
        h160 = self.hash160(compressed)
        if testnet:
            prefix = b'\x6f'
        else:
            prefix = b'\x00'
        return encode_base58_checksum(prefix + h160)

    def bech32_address(self, testnet=False):
        '''Returns the address string'''
        from script import p2wpkh_script
        h160 = self.hash160()
        raw = p2wpkh_script(h160).raw_serialize()
        return encode_bech32_checksum(raw, testnet)

    @classmethod
    def parse(self, sec_bin):
        '''returns a Point object from a SEC binary (not hex)'''
        if sec_bin[0] == 4:
            x = int.from_bytes(sec_bin[1:33], 'big')
            y = int.from_bytes(sec_bin[33:65], 'big')
            return S256Point(usec=sec_bin)
        else:
            return S256Point(csec=sec_bin)


G = S256Point(usec=bytes.fromhex('0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8'))


class S256Test(TestCase):

    def test_pubpoint(self):
        # write a test that tests the public point for the following
        points = (
            # secret, usec
            (7, '045cbdf0646e5db4eaa398f365f2ea7a0e3d419b7e0330e39ce92bddedcac4f9bc6aebca40ba255960a3178d6d861a54dba813d0b813fde7b5a5082628087264da'),
            (1485, '04c982196a7466fbbbb0e27a940b6af926c1a74d5ad07128c82824a11b5398afda7a91f9eae64438afb9ce6448a1c133db2d8fb9254e4546b6f001637d50901f55'),
            (2**128, '048f68b9d2f63b5f339239c1ad981f162ee88c5678723ea3351b7b444c9ec4c0da662a9f2dba063986de1d90c2b6be215dbbea2cfe95510bfdf23cbf79501fff82'),
            (2**240 + 2**31, '049577ff57c8234558f293df502ca4f09cbc65a6572c842b39b366f2171794511610b49c67fa9365ad7b90dab070be339a1daf9052373ec30ffae4f72d5e66d053'),
        )

        # iterate over points
        for secret, usec in points:
            # initialize the secp256k1 point (S256Point)
            point = S256Point(usec=bytes.fromhex(usec))
            # check that the secret*G is the same as the point
            self.assertEqual(secret * G, point)

    def test_verify(self):
        point = S256Point(
            bytes.fromhex('04887387e452b8eacc4acfde10d9aaf7f6d9a0f975aabb10d006e4da568744d06c61de6d95231cd89026e286df3b6ae4a894a3378e393e93a0f45b666329a0ae34'))
        tests = (
            (
                0xec208baa0fc1c19f708a9ca96fdeff3ac3f230bb4a7ba4aede4942ad003c0f60,
                '3045022100ac8d1c87e51d0d441be8b3dd5b05c8795b48875dffe00b7ffcfac23010d3a3950220068342ceff8935ededd102dd876ffd6ba72d6a427a3edb13d26eb0781cb423c4',
            ),
            (
                0x7c076ff316692a3d7eb3c3bb0f8b1488cf72e1afcd929e29307032997a838a3d,
                '3044022000eff69ef2b1bd93a66ed5219add4fb51e11a840f404876325a1e8ffe0529a2c022038df8011e682d839e75159debf909408cb3f12ae472b1d88cf6280cf01c6568b',
            ),
        )
        for z, der_hex in tests:
            der = bytes.fromhex(der_hex)
            self.assertTrue(point.verify(z, Signature(der=der)))

    def test_sec(self):
        tests = (
            (
                999**3,
                '049d5ca49670cbe4c3bfa84c96a8c87df086c6ea6a24ba6b809c9de234496808d56fa15cc7f3d38cda98dee2419f415b7513dde1301f8643cd9245aea7f3f911f9',
                '039d5ca49670cbe4c3bfa84c96a8c87df086c6ea6a24ba6b809c9de234496808d5',
            ),
            (
                123,
                '04a598a8030da6d86c6bc7f2f5144ea549d28211ea58faa70ebf4c1e665c1fe9b5204b5d6f84822c307e4b4a7140737aec23fc63b65b35f86a10026dbd2d864e6b',
                '03a598a8030da6d86c6bc7f2f5144ea549d28211ea58faa70ebf4c1e665c1fe9b5',
            ),
            (
                42424242,
                '04aee2e7d843f7430097859e2bc603abcc3274ff8169c1a469fee0f20614066f8e21ec53f40efac47ac1c5211b2123527e0e9b57ede790c4da1e72c91fb7da54a3',
                '03aee2e7d843f7430097859e2bc603abcc3274ff8169c1a469fee0f20614066f8e',
            ),
        )
        for coefficient, usec_hex, csec_hex in tests:
            point = coefficient * G
            usec = bytes.fromhex(usec_hex)
            csec = bytes.fromhex(csec_hex)
            self.assertEqual(point.sec(compressed=False), usec)
            self.assertEqual(point.sec(compressed=True), csec)
            computed = S256Point.parse(usec)
            self.assertEqual(point, computed)
            computed = S256Point.parse(csec)
            self.assertEqual(point, computed)

    def test_address(self):
        tests = (
            (
                888**3,
                '148dY81A9BmdpMhvYEVznrM45kWN32vSCN',
                'mnabU9NCcRE5zcNZ2C16CnvKPELrFvisn3',
                'bc1qyfvunnpszmjwcqgfk9dsne6j4edq3fglx9y5x7',
                'tb1qyfvunnpszmjwcqgfk9dsne6j4edq3fglvrl8ad',
            ),
            (
                321,
                '1FNgueDbMYjNQ8HT77sHKxTwdrHMdTGwyN',
                'mfx3y63A7TfTtXKkv7Y6QzsPFY6QCBCXiP',
                'bc1qnk4u7vkat6ck9t4unlgvvle8dhsqp40mrssamm',
                'tb1qnk4u7vkat6ck9t4unlgvvle8dhsqp40mfktwqg',
            ),
            (
                4242424242,
                '1HUYfVCXEmp76uh17bE2gA72Vuqv4wrM1a',
                'mgY3bVusRUL6ZB2Ss999CSrGVbdRwVpM8s',
                'bc1qkjm6e3c79zy7clsfx86q4pvy46ccc5u9xa6f6e',
                'tb1qkjm6e3c79zy7clsfx86q4pvy46ccc5u9vmp6p2',
            ),
        )
        for secret, mainnet_legacy, testnet_legacy, mainnet_bech32, testnet_bech32 in tests:
            point = secret * G
            self.assertEqual(
                point.address(testnet=False), mainnet_legacy)
            self.assertEqual(
                point.address(compressed=False, testnet=True), testnet_legacy)
            self.assertEqual(
                point.bech32_address(testnet=False), mainnet_bech32)
            self.assertEqual(
                point.bech32_address(testnet=True), testnet_bech32)


class Signature:

    def __init__(self, der=None, c=None):
        if der:
            self.der_cache = der
            self.c = ffi.new('secp256k1_ecdsa_signature *')
            if not lib.secp256k1_ecdsa_signature_parse_der(GLOBAL_CTX, self.c, der, len(der)):
                raise RuntimeError('badly formatted signature {}'.format(der.hex()))
        elif c:
            self.c = c
            self.der_cache = None
        else:
            raise RuntimeError('need der or c object')

    def __eq__(self, other):
        return self.der() == other.der()

    def __repr__(self):
        return 'Signature()'.format(self.der().hex())

    def der(self):
        if not self.der_cache:
            der = ffi.new('unsigned char[72]')
            der_length = ffi.new('size_t *', 72)
            lib.secp256k1_ecdsa_signature_serialize_der(GLOBAL_CTX, der, der_length, self.c)
            self.der_cache = bytes(ffi.buffer(der, der_length[0]))
        return self.der_cache

    def cdata(self):
        return self.c


class SignatureTest(TestCase):

    def test_der(self):
        tests = (
            '3045022100ed81ff192e75a3fd2304004dcadb746fa5e24c5031ccfcf21320b0277457c98f02207a986d955c6e0cb35d446a89d3f56100f4d7f67801c31967743a9c8e10615bed',
        )
        for der_hex in tests:
            der = bytes.fromhex(der_hex)
            sig = Signature(der)
            self.assertTrue('Signature' in sig.__repr__())
            computed = sig.der()
            self.assertEqual(der, computed)


class PrivateKey:

    def __init__(self, secret):
        self.secret = secret
        self.point = secret * G

    def sign(self, z):
        secret = self.secret.to_bytes(32, 'big')
        msg = z.to_bytes(32, 'big')
        csig = ffi.new('secp256k1_ecdsa_signature *')
        if not lib.secp256k1_ecdsa_sign(GLOBAL_CTX, csig, msg, secret, ffi.NULL, ffi.NULL):
            raise RuntimeError('something went wrong with c signing')
        sig = Signature(c=csig)
        if not self.point.verify(z, sig):
            raise RuntimeError('something went wrong with signing')
        return sig

    def wif(self, compressed=True, testnet=False):
        # convert the secret from integer to a 32-bytes in big endian using num.to_bytes(32, 'big')
        secret_bytes = self.secret.to_bytes(32, 'big')
        # prepend b'\xef' on testnet, b'\x80' on mainnet
        if testnet:
            prefix = b'\xef'
        else:
            prefix = b'\x80'
        # append b'\x01' if compressed
        if compressed:
            suffix = b'\x01'
        else:
            suffix = b''
        # encode_base58_checksum the whole thing
        return encode_base58_checksum(prefix + secret_bytes + suffix)


class PrivateKeyTest(TestCase):

    def test_sign(self):
        pk = PrivateKey(N-99)
        z = N-48
        sig = pk.sign(z)
        self.assertTrue(pk.point.verify(z, sig))
        pk = PrivateKey(N-99)
        z = N+99
        sig = pk.sign(z)
        self.assertTrue(pk.point.verify(z, sig))

    def test_wif(self):
        pk = PrivateKey(2**256 - 2**199)
        expected = 'L5oLkpV3aqBJ4BgssVAsax1iRa77G5CVYnv9adQ6Z87te7TyUdSC'
        self.assertEqual(pk.wif(compressed=True, testnet=False), expected)
        pk = PrivateKey(2**256 - 2**201)
        expected = '93XfLeifX7Jx7n7ELGMAf1SUR6f9kgQs8Xke8WStMwUtrDucMzn'
        self.assertEqual(pk.wif(compressed=False, testnet=True), expected)
        pk = PrivateKey(0x0dba685b4511dbd3d368e5c4358a1277de9486447af7b3604a69b8d9d8b7889d)
        expected = '5HvLFPDVgFZRK9cd4C5jcWki5Skz6fmKqi1GQJf5ZoMofid2Dty'
        self.assertEqual(pk.wif(compressed=False, testnet=False), expected)
        pk = PrivateKey(0x1cca23de92fd1862fb5b76e5f4f50eb082165e5191e116c18ed1a6b24be6a53f)
        expected = 'cNYfWuhDpbNM1JWc3c6JTrtrFVxU4AGhUKgw5f93NP2QaBqmxKkg'
        self.assertEqual(pk.wif(compressed=True, testnet=True), expected)
