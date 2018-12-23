import getpass

from Crypto.Cipher import AES
from io import BytesIO
from logging import getLogger
from mock import patch
from os import unlink
from os.path import exists, isfile
from secrets import token_bytes
from time import time, sleep
from unittest import TestCase

from block import Block
from chainstore import BlockStore
from hd import HDPrivateKey, HDPublicKey
from helper import (
    encode_varint,
    hash256,
    int_to_little_endian,
    little_endian_to_int,
    read_varint,
    sha256,
)
from network import (
    BLOCK_DATA_TYPE,
    SimpleNode,
    GetCFiltersMessage,
    CFilterMessage,
    GetDataMessage,
)
from script import Script, address_to_script_pubkey
from tx import TxStore, Tx, TxIn, TxOut


LOGGER = getLogger(__name__)
KEY_ITERATIONS = 10000


class TXO:

    def __init__(self, tx_id, tx_index, amount, script_pubkey, path):
        self.tx_id = tx_id
        self.tx_index = tx_index
        self.amount = amount
        self.script_pubkey = script_pubkey
        self.path = path

    @classmethod
    def parse(cls, s):
        tx_id = s.read(32)
        tx_index = little_endian_to_int(s.read(4))
        amount = little_endian_to_int(s.read(8))
        script_pubkey = Script.parse(s)
        path_0 = read_varint(s)
        path_1 = read_varint(s)
        return cls(tx_id, tx_index, amount, script_pubkey, (path_0, path_1))

    def serialize(self):
        result = self.tx_id
        result += int_to_little_endian(self.tx_index, 4)
        result += int_to_little_endian(self.amount, 8)
        result += self.script_pubkey.serialize()
        result += encode_varint(self.path[0])
        result += encode_varint(self.path[1])
        return result


class UTXO:

    def __init__(self, txo):
        self.txo = txo

    @classmethod
    def parse(cls, s):
        txo = TXO.parse(s)
        return cls(txo)

    def serialize(self):
        result = self.txo.serialize()
        return result


class STXO:

    def __init__(self, txo, spending_tx_id, spending_tx_index):
        self.txo = txo
        self.spending_tx_id = spending_tx_id
        self.spending_tx_index = spending_tx_index

    @classmethod
    def parse(cls, s):
        txo = TXO.parse(s)
        spending_tx_id = s.read(32)
        spending_tx_index = little_endian_to_int(s.read(4))
        return cls(txo, spending_tx_id, spending_tx_index)

    def serialize(self):
        result = self.txo.serialize()
        result += self.spending_tx_id
        result += int_to_little_endian(self.spending_tx_index, 4)
        return result


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
        for i in range(5):
            # prompt for a password
            password = getpass.getpass().encode('ascii')
            cipher = self.cipher(self.salt, password)
            zprv = cipher.decrypt(self.encrypted_data)
            try:
                self.private_key = HDPrivateKey.parse(BytesIO(zprv))
                break
            except ValueError:
                print('wrong password, you have {} more tries'.format(4-i))
                sleep(1 << (i*2))
        else:
            raise RuntimeError('could not unlock the wallet')    
        self.expires = int(time()) + 300
        return True

    def locked(self):
        if time() > self.expires:
            self.private_key = None
        return self.private_key is None

    def get_key(self, path):
        if self.locked():
            self.unlock()
        if self.private_key.testnet:
            network = b"1'"
        else:
            network = b"0'"
        full_path = b"m/84'/" + network + b"/0'/" + '{}/{}'.format(path[0], path[1]).encode('ascii')
        return self.private_key.traverse(full_path).private_key

    def sign(self, tx_obj, paths):
        if self.locked():
            self.unlock()
        for input_index, path in enumerate(paths):
            tx_obj.sign_input_p2wpkh(input_index, self.get_key(path))

    @classmethod
    def generate(cls, testnet=False):
        password = getpass.getpass().encode('ascii')
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
        password = getpass.getpass().encode('ascii')
        salt = token_bytes(32)
        cipher = cls.cipher(salt, password)
        plaintext = private_key.zprv().encode('ascii')
        plaintext += b'\x00' * ((16 - len(plaintext)) % 16)
        encrypted_private = cls(salt, cipher.encrypt(plaintext))
        encrypted_private.private_key = private_key
        encrypted_private.expires = int(time()) + 300
        return encrypted_private


class Wallet:

    def __init__(self, encrypted_private, public, next_external, next_internal, creation_height, sync_height, utxos, stxos, filename):
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
        self.node = SimpleNode(host='192.168.1.200', testnet=self.testnet)
        self.block_store = BlockStore(node=self.node, include=self.sync_height)
        sleep(1)
        if not self.sync_height:
            # this is a new wallet
            self.creation_height = self.sync_height = self.node.latest_block

    @classmethod
    def create(cls, filename='wallet.data', testnet=False):
        if isfile(filename):
            raise RuntimeError('file exists: {}'.format(filename))
        mnemonic, encrypted_private = EncryptedPrivateKey.generate(testnet)
        if testnet:
            network = b"1'"
        else:
            network = b"0'"
        path = b"m/84'/" + network + b"/0'"
        public = encrypted_private.private_key.traverse(path).pub
        wallet = cls(encrypted_private, public, 0, 0, None, None, [], [], filename=filename)
        wallet.save()
        return mnemonic, wallet

    @classmethod
    def recover(cls, mnemonic, filename='wallet.data', testnet=False):
        if isfile(filename):
            raise RuntimeError('file exists: {}'.format(filename))
        encrypted_private = EncryptedPrivateKey.from_mnemonic(mnemonic, testnet)
        if testnet:
            network = b"1'"
        else:
            network = b"0'"
        path = b"m/84'/" + network + b"/0'"
        public = encrypted_private.private_key.traverse(path).pub
        wallet = cls(encrypted_private, public, 0, 0, None, None, [], [], filename=filename)
        # TODO: determine how many addresses have been used
        # TODO: determine what height to start at
        wallet.save()
        return wallet
        
    @classmethod
    def open(cls, filename='wallet.data'):
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
        self.update(self.creation_height)
    
    def update(self, height=None):
        '''Scan from the block at height to the block that
        the block_store has'''
        self.block_store.update()
        if height is None:
            height = self.sync_height
        # start from height, download the compact filters
        num_requests, r = divmod(self.block_store.store_height() - height, 1000)
        if r > 0:
            num_requests += 1
        getdata = GetDataMessage()
        script_pubkey_lookup = self.script_pubkey_lookup()
        LOGGER.info('scanning blocks for relevant transactions')
        for i in range(num_requests):
            start_height = height + i*1000
            if i == num_requests - 1:
                end_height = self.block_store.store_height()
            else:
                end_height = height + (i+1)*1000 - 1
            stop_hash = self.block_store.header_at_height(end_height).hash()
            LOGGER.info('scanning from {} to {}'.format(start_height, end_height))
            getcfilters = GetCFiltersMessage(
                start_height=start_height,
                stop_hash=stop_hash,
            )
            self.node.send(getcfilters)
            for h in range(start_height, end_height+1):
                cfilter = self.node.wait_for(CFilterMessage)
                header = self.block_store.header_at_height(h)
                if header.hash() != cfilter.block_hash:
                    raise RuntimeError('bad block')
                computed = hash256(cfilter.filter_bytes)[::-1]
                if computed != header.cfhash:
                    raise RuntimeError('not the right cf hash')
                if script_pubkey_lookup.keys() in cfilter:
                    LOGGER.info('interesting block {}'.format(h))
                    getdata.add(BLOCK_DATA_TYPE, cfilter.block_hash)
        # download the blocks we know are interesting
        self.node.send(getdata)
        for _, block_hash in getdata.data:
            b = self.node.wait_for(Block)
            if b.hash() != block_hash:
                raise RuntimeError('wrong block sent')
            for tx_obj in b.txs:
                add_tx = False
                tx_hash = tx_obj.hash()
                for i, tx_in in enumerate(tx_obj.tx_ins):
                    # if this transaction has a utxo as an input (spending)
                    key = (tx_in.prev_tx, tx_in.prev_index)
                    if self.utxo_lookup.get(key):
                        utxo = self.utxo_lookup.pop(key)
                        self.stxo_lookup[(tx_hash, i)] = STXO(utxo.txo, tx_hash, i)
                        add_tx = True
                for i, tx_out in enumerate(tx_obj.tx_outs):
                    # if this transaction has an output that's ours (receiving)
                    raw_script_pubkey = tx_out.script_pubkey.raw_serialize()
                    if raw_script_pubkey in script_pubkey_lookup.keys():
                        txo = TXO(tx_hash, i, tx_out.amount,
                                  tx_out.script_pubkey, script_pubkey_lookup[raw_script_pubkey])
                        self.utxo_lookup[(tx_hash, i)] = UTXO(txo)
                        add_tx = True
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
        self.assertTrue(w.encrypted_private.unlock())
        w.save()
        w2 = Wallet.open(filename=filename)
        self.assertTrue(w.testnet)
        self.assertEqual(w.public.zpub(), w2.public.zpub())
        unlink(filename)
        w3 = Wallet.recover(mnemonic, filename=filename, testnet=True)
        self.assertEqual(w.public.zpub(), w3.public.zpub())
