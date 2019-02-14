import getpass

from Crypto.Cipher import AES
from io import BytesIO
from logging import getLogger
from mock import patch, Mock
from os import unlink
from os.path import exists, isfile
from secrets import token_bytes
from time import time, sleep
from unittest import TestCase

from block import Block
from chainstore import BlockStore
from hd import HDPrivateKey, HDPublicKey
from helper import (
    encode_gcs,
    encode_varint,
    filter_null,
    hash256,
    int_to_little_endian,
    little_endian_to_int,
    read_varint,
    sha256,
)
from network import (
    BLOCK_DATA_TYPE,
    CFilterMessage,
    GetCFiltersMessage,
    GetDataMessage,
    NetworkEnvelope,
    SimpleNode,
    VerAckMessage,
)
from script import Script, address_to_script_pubkey, p2wpkh_script
from tx import TxStore, Tx, TxIn, TxOut


LOGGER = getLogger(__name__)
KEY_ITERATIONS = 10000


class TXO:

    def __init__(self, tx_id, tx_index, amount, script_pubkey, block_height, path):
        self.tx_id = tx_id
        self.tx_index = tx_index
        self.amount = amount
        self.script_pubkey = script_pubkey
        self.block_height = block_height
        self.path = path

    @classmethod
    def parse(cls, s):
        tx_id = s.read(32)
        tx_index = little_endian_to_int(s.read(4))
        amount = little_endian_to_int(s.read(8))
        script_pubkey = Script.parse(s)
        block_height = read_varint(s)
        path_0 = read_varint(s)
        path_1 = read_varint(s)
        return cls(tx_id, tx_index, amount, script_pubkey, block_height, (path_0, path_1))

    def serialize(self):
        result = self.tx_id
        result += int_to_little_endian(self.tx_index, 4)
        result += int_to_little_endian(self.amount, 8)
        result += self.script_pubkey.serialize()
        result += encode_varint(self.block_height)
        result += encode_varint(self.path[0])
        result += encode_varint(self.path[1])
        return result


class UTXO:

    def __init__(self, txo):
        self.txo = txo

    def __repr__(self):
        return '{amount} BTC {address} {path} {tx_id}:{tx_index}:{block_height}'.format(
            tx_id=self.txo.tx_id.hex(),
            tx_index=self.txo.tx_index,
            amount=self.txo.amount / 100000000,
            address=self.txo.script_pubkey.address(testnet=True),
            path=self.txo.path,
            block_height=self.txo.block_height,
        )

    @classmethod
    def parse(cls, s):
        txo = TXO.parse(s)
        return cls(txo)

    def serialize(self):
        result = self.txo.serialize()
        return result


class STXO:

    def __init__(self, txo, spending_tx_id, spending_tx_index, spending_height):
        self.txo = txo
        self.spending_tx_id = spending_tx_id
        self.spending_tx_index = spending_tx_index
        self.spending_height = spending_height

    def __repr__(self):
        return '{} BTC {}:{}:{}'.format(
            self.txo.amount / 100000000,
            self.spending_tx_id.hex(),
            self.spending_tx_index,
            self.spending_height,
        )

    @classmethod
    def parse(cls, s):
        txo = TXO.parse(s)
        spending_tx_id = s.read(32)
        spending_tx_index = little_endian_to_int(s.read(4))
        spending_height = read_varint(s)
        return cls(txo, spending_tx_id, spending_tx_index, spending_height)

    def serialize(self):
        result = self.txo.serialize()
        result += self.spending_tx_id
        result += int_to_little_endian(self.spending_tx_index, 4)
        result += encode_varint(self.spending_height)
        return result


class TXOTest(TestCase):

    def test_txo(self):
        tx_id = b'\x00' * 32
        tx_index = 0
        amount = 1000000
        script_pubkey = Script([0x76, 0xa9, b'\x00' * 20, 0x88, 0xac])
        block_height = 525000
        path = (0,0)
        txo = TXO(tx_id, tx_index, amount, script_pubkey, block_height, path)
        utxo = UTXO(txo)
        want = '00000000000000000000000000000000000000000000000000000000000000000000000040420f00000000001976a914000000000000000000000000000000000000000088acfec80208000000'
        self.assertEqual(utxo.serialize().hex(), want)
        s = BytesIO(bytes.fromhex(want))
        utxo_parsed = UTXO.parse(s)
        self.assertEqual(utxo.txo.tx_id, utxo_parsed.txo.tx_id)
        self.assertEqual(utxo.txo.tx_index, utxo_parsed.txo.tx_index)
        self.assertEqual(utxo.txo.amount, utxo_parsed.txo.amount)
        self.assertEqual(utxo.txo.script_pubkey, utxo_parsed.txo.script_pubkey)
        self.assertEqual(utxo.txo.block_height, utxo_parsed.txo.block_height)
        self.assertEqual(utxo.txo.path, utxo_parsed.txo.path)
        want = '0.01 BTC mfWxJ45yp2SFn7UciZyNpvDKrzbhyfKrY8 (0, 0) 0000000000000000000000000000000000000000000000000000000000000000:0:525000'
        self.assertEqual(utxo.__repr__(), want)
        spending_tx_id = b'\x11' * 32
        spending_tx_index = 1
        spending_height = 535000
        stxo = STXO(txo, spending_tx_id, spending_tx_index, spending_height)
        want = '00000000000000000000000000000000000000000000000000000000000000000000000040420f00000000001976a914000000000000000000000000000000000000000088acfec80208000000111111111111111111111111111111111111111111111111111111111111111101000000fed8290800'
        self.assertEqual(stxo.serialize().hex(), want)
        s = BytesIO(bytes.fromhex(want))
        stxo_parsed = STXO.parse(s)
        self.assertEqual(stxo.spending_tx_id, stxo_parsed.spending_tx_id)
        self.assertEqual(stxo.spending_tx_index, stxo_parsed.spending_tx_index)
        self.assertEqual(stxo.spending_height, stxo_parsed.spending_height)
        want = '0.01 BTC 1111111111111111111111111111111111111111111111111111111111111111:1:535000'
        self.assertEqual(stxo.__repr__(), want)


class EncryptedPrivateKey:

    def __init__(self, salt, encrypted_data):
        self.salt = salt
        self.encrypted_data = encrypted_data
        self.expires = 0
        self.private_key = None

    @classmethod
    def parse(cls, s):
        salt = s.read(32)
        data_len = read_varint(s)
        encrypted_data = s.read(data_len)
        return cls(salt, encrypted_data)

    def serialize(self):
        result = self.salt
        result += encode_varint(len(self.encrypted_data))
        result += self.encrypted_data
        return result

    @classmethod
    def cipher(cls, salt, password):
        key = password + salt
        for _ in range(KEY_ITERATIONS):
            key = sha256(key)
        return AES.new(key, AES.MODE_ECB)

    def unlock(self):
        if not self.locked():
            return
        for i in range(3):
            # prompt for a password
            password = getpass.getpass(prompt='Password: ').encode('ascii')
            cipher = self.cipher(self.salt, password)
            zprv = cipher.decrypt(self.encrypted_data)
            try:
                self.private_key = HDPrivateKey.parse(BytesIO(zprv))
                break
            except ValueError:
                print('wrong password, you have {} more tries'.format(2-i))
                sleep(1 << i)
        else:
            return False
        self.expires = int(time()) + 300
        return True

    def locked(self):
        if time() > self.expires:
            self.private_key = None
        return self.private_key is None

    def get_key(self, path):
        self.unlock()
        if self.private_key.testnet:
            network = b"1'"
        else:
            network = b"0'"
        full_path = b"m/84'/" + network + b"/0'/" + '{}/{}'.format(path[0], path[1]).encode('ascii')
        return self.private_key.traverse(full_path)

    def sign(self, tx_obj, paths):
        self.unlock()
        for input_index, path in enumerate(paths):
            tx_obj.sign_input_p2wpkh(input_index, self.get_key(path).private_key)
        return tx_obj.verify()

    @classmethod
    def generate(cls, testnet=False):
        password = getpass.getpass(prompt='New Password: ').encode('ascii')
        salt = token_bytes(32)
        cipher = cls.cipher(salt, password)
        mnemonic, private_key = HDPrivateKey.generate(testnet=testnet)
        plaintext = private_key.zprv().encode('ascii')
        plaintext += b'\x00' * ((16 - len(plaintext)) % 16)
        encrypted_private = cls(salt, cipher.encrypt(plaintext))
        encrypted_private.private_key = private_key
        encrypted_private.expires = int(time()) + 300
        return mnemonic, encrypted_private

    @classmethod
    def from_mnemonic(cls, mnemonic, testnet=False):
        private_key = HDPrivateKey.from_mnemonic(mnemonic, testnet=testnet)
        password = getpass.getpass(prompt='New Password: ').encode('ascii')
        salt = token_bytes(32)
        cipher = cls.cipher(salt, password)
        plaintext = private_key.zprv().encode('ascii')
        plaintext += b'\x00' * ((16 - len(plaintext)) % 16)
        encrypted_private = cls(salt, cipher.encrypt(plaintext))
        encrypted_private.private_key = private_key
        encrypted_private.expires = int(time()) + 300
        return encrypted_private


class EncryptedPrivateTest(TestCase):

    @patch('getpass.getpass')
    def test_generate(self, gp):
        gp.return_value = 'password'
        mnemonic, enc = EncryptedPrivateKey.generate(testnet=True)
        self.assertTrue(mnemonic)
        serialized = enc.serialize()
        self.assertEqual(len(serialized), 145)
        stream = BytesIO(serialized)
        parsed = EncryptedPrivateKey.parse(stream)
        self.assertEqual(enc.salt, parsed.salt)
        self.assertEqual(enc.encrypted_data, parsed.encrypted_data)
        self.assertFalse(enc.locked())
        self.assertTrue(enc.expires > 0)
        self.assertFalse(enc.locked())
        enc.expires = 0
        self.assertTrue(enc.locked())
        self.assertTrue(enc.unlock())
        self.assertFalse(enc.locked())
        enc.expires = 0
        gp.return_value = 'wrong'
        self.assertFalse(enc.unlock())

    @patch('getpass.getpass')
    def test_recover(self, gp):
        gp.return_value = 'password'
        mnemonic = 'method wire potato cotton fame can repair mother elder festival hurry trophy'
        enc = EncryptedPrivateKey.from_mnemonic(mnemonic)
        addr = 'bc1qq5qrkcc5d0f3chmmwsc50ap8l8ukjjyc8je2wg'
        path = (0, 0)
        pub_key = enc.get_key(path).pub
        self.assertEqual(pub_key.bech32_address(), addr)
        enc = EncryptedPrivateKey.from_mnemonic(mnemonic, testnet=True)
        addr = 'tb1qtvaq0px8vaxlxez4gx3e78gqv8a06ysnp6me4x'
        pub_key = enc.get_key(path).pub
        self.assertEqual(pub_key.bech32_address(), addr)

    @patch('getpass.getpass')
    def test_sign(self, gp):
        gp.return_value = 'password'
        mnemonic = 'method wire potato cotton fame can repair mother elder festival hurry trophy'
        enc = EncryptedPrivateKey.from_mnemonic(mnemonic, testnet=True)
        tx_id = bytes.fromhex(
            '07affe8b0ef5f009eef5399c20586b3181103564e8ffe444631dcae20389738c')
        tx_index = 0
        amount = 12753130
        path = (0, 0)
        pub_key = enc.get_key(path).pub
        script_pubkey = p2wpkh_script(pub_key.hash160())
        tx_in = TxIn(tx_id, tx_index)
        tx_out = TxOut(amount - 5000, script_pubkey)
        tx_obj = Tx(1, [tx_in], [tx_out], 0, testnet=True, segwit=True)
        self.assertTrue(enc.sign(tx_obj, [path]))


class Wallet:

    def __init__(self, encrypted_private, public, next_external, next_internal, creation_height, sync_height, utxos, stxos, filename, host=None):
        self.encrypted_private = encrypted_private
        self.public = public
        self.next_external = next_external
        self.next_internal = next_internal
        self.creation_height = creation_height
        self.sync_height = sync_height
        self.utxo_lookup = {(utxo.txo.tx_id, utxo.txo.tx_index): utxo for utxo in utxos}
        self.stxo_lookup = {(stxo.spending_tx_id, stxo.spending_tx_index): stxo for stxo in stxos}
        self.filename = filename
        self.testnet = self.public.testnet
        self.tx_store = TxStore.get_store(testnet=self.testnet)
        if host:
            self.connect(host)

    def connect(self, host):
        self.node = SimpleNode(host=host, testnet=self.testnet)
        self.block_store = BlockStore(node=self.node, include=self.sync_height)
        sleep(1)
        if not self.creation_height:
            # this is a new wallet
            self.creation_height = self.sync_height = self.node.latest_block

    def __repr__(self):
        return '{} {}'.format(self.next_external, self.next_internal)
            
    @classmethod
    def create(cls, filename=None, testnet=False):
        if filename is None:
            if testnet:
                filename = 'testnet.wallet'
            else:
                filename = 'mainnet.wallet'
        if isfile(filename):
            raise RuntimeError('file exists: {}'.format(filename))
        mnemonic, encrypted_private = EncryptedPrivateKey.generate(testnet)
        if testnet:
            network = b"1'"
        else:
            network = b"0'"
        path = b"m/84'/" + network + b"/0'"
        public = encrypted_private.private_key.traverse(path).pub
        wallet = cls(encrypted_private, public, 0, 0, 0, 0, [], [], filename=filename)
        wallet.save()
        return mnemonic, wallet

    @classmethod
    def recover(cls, mnemonic, filename=None, testnet=False):
        if filename is None:
            if testnet:
                filename = 'testnet.wallet'
            else:
                filename = 'mainnet.wallet'
        if isfile(filename):
            raise RuntimeError('file exists: {}'.format(filename))
        encrypted_private = EncryptedPrivateKey.from_mnemonic(mnemonic, testnet)
        if testnet:
            network = b"1'"
        else:
            network = b"0'"
        path = b"m/84'/" + network + b"/0'"
        public = encrypted_private.private_key.traverse(path).pub
        wallet = cls(encrypted_private, public, 0, 0, 0, 0, [], [], filename=filename)
        # TODO: determine how many addresses have been used
        # TODO: determine what height to start at
        wallet.save()
        return wallet
        
    @classmethod
    def open(cls, filename='testnet.wallet'):
        if not isfile(filename):
            raise RuntimeError('No such file {}'.format(filename))
        with open(filename, 'rb') as f:
            encrypted_private = EncryptedPrivateKey.parse(f)
            public = HDPublicKey.parse(f)
            next_external = read_varint(f)
            next_internal = read_varint(f)
            creation_height = read_varint(f)
            sync_height = read_varint(f)
            num_utxos = read_varint(f)
            utxos = []
            for _ in range(num_utxos):
                utxos.append(UTXO.parse(f))
            num_stxos = read_varint(f)
            stxos = []
            for _ in range(num_stxos):
                stxos.append(STXO.parse(f))
        return cls(
            encrypted_private, public, next_external, next_internal,
            creation_height, sync_height, utxos, stxos, filename=filename)

    def save(self):
        with open(self.filename, 'wb') as f:
            f.write(self.encrypted_private.serialize())
            f.write(self.public.serialize())
            f.write(encode_varint(self.next_external))
            f.write(encode_varint(self.next_internal))
            f.write(encode_varint(self.creation_height))
            f.write(encode_varint(self.sync_height))
            utxos = [u for u in self.utxo_lookup.values()]
            f.write(encode_varint(len(utxos)))
            for utxo in utxos:
                f.write(utxo.serialize())
            stxos = [s for s in self.stxo_lookup.values()]
            f.write(encode_varint(len(stxos)))
            for stxo in stxos:
                f.write(stxo.serialize())

    def address(self):
        pub = self.public.child(0).child(self.next_external)
        self.next_external += 1
        self.save()
        return pub.bech32_address()

    def addresses(self):
        external, internal = [], []
        for i in range(self.next_external):
            pub = self.public.child(0).child(i)
            external.append(pub.bech32_address())
        for i in range(self.next_internal):
            pub = self.public.child(1).child(i)
            internal.append(pub.bech32_address())
        return external, internal

    def get_utxos(self):
        return [v for v in self.utxo_lookup.values()]

    def get_history(self):
        return [v for v in self.stxo_lookup.values()]

    def change_script_pubkey(self):
        pub = self.public.child(1).child(self.next_internal)
        self.next_internal += 1
        self.save()
        return pub.p2wpkh_script_pubkey()

    def script_pubkey_lookup(self):
        script_pubkey_lookup = {}
        external = self.public.child(0)
        for i in range(self.next_external):
            script_pubkey_lookup[external.child(i).p2wpkh_script_pubkey().raw_serialize()] = (0, i)
        internal = self.public.child(1)
        for i in range(self.next_internal):
            script_pubkey_lookup[internal.child(i).p2wpkh_script_pubkey().raw_serialize()] = (1, i)
        return script_pubkey_lookup

    def rescan(self):
        self.utxo_lookup = {}
        self.stxo_lookup = {}
        self.update(self.creation_height)
    
    def update(self, height=None):
        '''Scan from the block at height to the block that
        the block_store has'''
        self.block_store.update()
        if height is None:
            height = self.sync_height
        block_hashes = self.get_relevant_block_hashes(height)
        self.scan_blocks(block_hashes)

    def get_relevant_block_hashes(self, height):
        # start from height, download the compact filters
        num_requests, r = divmod(self.block_store.store_height() - height, 1000)
        if r > 0:
            num_requests += 1
        block_hashes = []
        script_pubkey_lookup = self.script_pubkey_lookup()
        LOGGER.info('scanning blocks for relevant transactions')
        for i in range(num_requests):
            start_height = height + i*1000
            if i == num_requests - 1:
                end_height = self.block_store.store_height()
            else:
                end_height = height + (i+1)*1000 - 1
            stop_hash = self.block_store.header_by_height(end_height).hash()
            LOGGER.info('scanning from {} to {}'.format(start_height, end_height))
            getcfilters = GetCFiltersMessage(
                start_height=start_height,
                stop_hash=stop_hash,
            )
            self.node.send(getcfilters)
            for h in range(start_height, end_height+1):
                cfilter = self.node.wait_for(CFilterMessage)
                header = self.block_store.header_by_height(h)
                if header.hash() != cfilter.block_hash:
                    raise RuntimeError('bad block')
                computed = hash256(cfilter.filter_bytes)[::-1]
                if computed != header.cfhash:
                    raise RuntimeError('not the right cf hash')
                if script_pubkey_lookup.keys() in cfilter:
                    LOGGER.info('interesting block {}: {}'.format(h, header.id()))
                    header.cfilter = cfilter
                    block_hashes.append(cfilter.block_hash)
        return block_hashes

    def scan_blocks(self, block_hashes):
        script_pubkey_lookup = self.script_pubkey_lookup()
        # download the blocks we know are interesting
        for h, b in self.node.get_blocks(block_hashes):
            if h != b.hash():
                raise RuntimeError('bad block: {} vs {}'.format(h.hex(), b.id()))
            header = self.block_store.header_by_hash(h)
            for raw_script_pubkey in b.get_outpoints():
                if raw_script_pubkey not in header.cfilter:
                    raise RuntimeError('script_pubkeys are not in the filter')
            for tx_obj in b.txs:
                add_tx = False
                tx_hash = tx_obj.hash()
                if not tx_obj.is_coinbase():
                    for i, tx_in in enumerate(tx_obj.tx_ins):
                        # if this transaction has a utxo as an input (spending)
                        key = (tx_in.prev_tx, tx_in.prev_index)
                        if self.utxo_lookup.get(key):
                            add_tx = True
                            utxo = self.utxo_lookup.pop(key)
                            self.stxo_lookup[key] = STXO(utxo.txo, tx_hash, i)
                for i, tx_out in enumerate(tx_obj.tx_outs):
                    # if this transaction has an output that's ours (receiving)
                    raw_script_pubkey = tx_out.script_pubkey.raw_serialize()
                    if raw_script_pubkey in script_pubkey_lookup.keys():
                        add_tx = True
                        txo = TXO(
                            tx_hash, i, tx_out.amount, tx_out.script_pubkey,
                            header.height,
                            script_pubkey_lookup[raw_script_pubkey])
                        self.utxo_lookup[key] = UTXO(txo)
                if add_tx:
                    LOGGER.info('interesting tx {}'.format(tx_obj.id()))
                    self.tx_store.add(tx_obj)
        self.sync_height = self.block_store.store_height()
        self.save()
        self.tx_store.save()

    def balance(self):
        balance = 0
        for utxo in self.utxo_lookup.values():
            balance += utxo.txo.amount
        return balance

    def spent(self):
        spent = 0
        for stxo in self.stxo_lookup.values():
            spent += stxo.txo.amount
        return spent

    def total_received(self):
        return self.balance() + self.spent()
    
    def simple_send(self, address, amount, satoshi_per_byte=1):
        if amount > self.balance():
            raise RuntimeError('Balance is less than how much you want to send')
        input_total = 0
        tx_ins = []
        paths = []
        # gather inputs using our utxos
        for utxo in self.utxo_lookup.values():
            input_total += utxo.txo.amount
            tx_ins.append(TxIn(utxo.txo.tx_id, utxo.txo.tx_index))
            paths.append(utxo.txo.path)
            if input_total > amount:
                break
            
        # target output
        tx_outs = [TxOut(amount, address_to_script_pubkey(address))]
        tx_outs_size = len(tx_outs[0].serialize())
        
        # calculate how much fees should be at this point
        # our utxos are always bech32, so each input is 32+4+1+4 = 41 bytes
        # our change outputs are bech32, so each output is 8+23 = 31 bytes
        # the witness will be 33 + 72 bytes per input but count 1/4
        tx_size = 4 + 1 + len(tx_ins)*41 + 1 + tx_outs_size + 31 + len(tx_ins) * (2 + 33 + 72)
        fee = tx_size * satoshi_per_byte
        if input_total < fee + amount:
            raise RuntimeError('Balance does not cover fees')

        # change output
        change_amount = input_total - amount - fee
        # don't bother if we're creating dust
        if change_amount > 200:
            tx_outs.append(TxOut(change_amount, self.change_script_pubkey()))

        # create transaction and sign
        tx_obj = Tx(1, tx_ins, tx_outs, 0, testnet=self.testnet, segwit=True)
        # signing the transaction
        self.encrypted_private.sign(tx_obj, paths)
        LOGGER.info('sending the transaction')
        return self.node.send_tx(tx_obj)


class WalletTest(TestCase):

    @patch('getpass.getpass')
    def test_create(self, gp):
        gp.return_value = 'password'
        filename = 'tmp.wallet'
        if exists(filename):
            unlink(filename)
        mnemonic, w = Wallet.create(filename=filename, testnet=True)
        w.save()
        w2 = Wallet.open(filename=filename)
        self.assertTrue(w.testnet)
        self.assertEqual(w.public.zpub(), w2.public.zpub())
        unlink(filename)
        w3 = Wallet.recover(mnemonic, filename=filename, testnet=True)
        self.assertEqual(w.public.zpub(), w3.public.zpub())

    @patch('getpass.getpass')
    def test_existing(self, gp):
        gp.return_value = 'password'
        filename = 'tmp.wallet'
        w = Wallet.open(filename=filename)
        self.assertTrue(w.testnet)
        self.assertEqual(len(w.utxo_lookup), 0)
        self.assertEqual(len(w.stxo_lookup), 0)
        w.save()

    @patch('getpass.getpass')
    @patch('socket.socket')
    def test_recover(self, mock_socket, gp):
        mock_socket.return_value.makefile.return_value = open('unittest.expected', 'rb')
        gp.return_value = 'password'
        filename = 'tmp.wallet'
        if exists(filename):
            unlink(filename)
        mnemonic = 'method wire potato cotton fame can repair mother elder festival hurry trophy'
        w = Wallet.recover(mnemonic, filename=filename, testnet=True)
        w.creation_height = 1455663
        w.next_external = 1
        self.assertEqual(w.__repr__(), '1 0')
        w.connect('nowhere')
        w.rescan()
        self.assertEqual(len(w.utxo_lookup), 1)
        tx_id = bytes.fromhex('07affe8b0ef5f009eef5399c20586b3181103564e8ffe444631dcae20389738c')
        utxo = w.get_utxos()[0]
        self.assertEqual(utxo.txo.tx_id, tx_id)
        self.assertEqual(utxo.txo.tx_index, 0)
        self.assertEqual(utxo.txo.amount, 12753130)
        self.assertEqual(utxo.txo.block_height, 1455664)
        self.assertEqual(w.get_history(), [])
        next_addr = w.address()
        self.assertEqual(next_addr, 'tb1qrj0d66a8m5awxe26smzsdqzc0ltpnerjelrvpw')
        change = w.change_script_pubkey()
        self.assertEqual(change.address(True), 'tb1qkrlhyzq4wgtpnlyduupeq7ee9ke9k7qnyv39mf')
        self.assertEqual(w.addresses(), (['tb1qtvaq0px8vaxlxez4gx3e78gqv8a06ysnp6me4x', 'tb1qrj0d66a8m5awxe26smzsdqzc0ltpnerjelrvpw'], ['tb1qkrlhyzq4wgtpnlyduupeq7ee9ke9k7qnyv39mf']))
        self.assertEqual(w.balance(), 12753130)
        self.assertEqual(w.spent(), 0)
        self.assertEqual(w.total_received(), 12753130)
