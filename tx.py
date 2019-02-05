from io import BytesIO
from logging import getLogger
from os.path import exists
from unittest import TestCase

import json
import requests

from ecc import PrivateKey
from helper import (
    decode_base58,
    decode_bech32,
    hash256,
    encode_varint,
    encode_varstr,
    hash160,
    int_to_little_endian,
    little_endian_to_int,
    read_varint,
    read_varstr,
    SIGHASH_ALL,
)
from script import (
    multisig_redeem_script,
    p2pkh_script,
    p2sh_script,
    p2wpkh_script,
    p2wsh_script,
    Script,
)


LOGGER = getLogger(__name__)


class TxStore:

    testnet_store = None
    mainnet_store = None

    @classmethod
    def get_store(cls, testnet=False):
        if testnet:
            if cls.testnet_store is None:
                cls.testnet_store = cls(testnet=True)
            return cls.testnet_store
        else:
            if cls.mainnet_store is None:
                cls.mainnet_store = cls(testnet=False)
            return cls.mainnet_store
    
    @classmethod
    def fetch(cls, tx_id, testnet=False):
        store = cls.get_store(testnet)
        result = store.get(bytes.fromhex(tx_id))
        if result is None:
            raise ValueError('no {} transaction with id {}'.format(testnet, tx_id))
        return result

    def __init__(self, testnet=False, filename=None):
        self.testnet = testnet
        if filename is None:
            if testnet:
                self.filename = 'testnet.txs'
            else:
                self.filename = 'mainnet.txs'
        else:
            self.filename = filename
        self.node = None
        self.tx_lookup = {}
        if exists(self.filename):
            with open(self.filename, 'rb') as f:
                num_txs = read_varint(f)
                for _ in range(num_txs):
                    tx_obj = Tx.parse(f, testnet=self.testnet)
                    self.tx_lookup[tx_obj.hash()] = tx_obj

    def save(self):
        with open(self.filename, 'wb') as f:
            f.write(encode_varint(len(self.tx_lookup)))
            for tx_hash in sorted(self.tx_lookup.keys()):
                tx_obj = self.tx_lookup[tx_hash]
                f.write(tx_obj.serialize())

    def add(self, tx_obj):
        self.tx_lookup[tx_obj.hash()] = tx_obj

    def get(self, tx_hash):
        return self.tx_lookup.get(tx_hash)


class Tx:
    command = b'tx'

    def __init__(self, version, tx_ins, tx_outs, locktime, testnet=False, segwit=False):
        self.version = version
        self.tx_ins = tx_ins
        self.tx_outs = tx_outs
        self.locktime = locktime
        self.testnet = testnet
        self.segwit = segwit
        self._hash_prevouts = None
        self._hash_sequence = None
        self._hash_outputs = None
        self.bip65 = True
        self.bip112 = True

    def __repr__(self):
        tx_ins = ''
        for tx_in in self.tx_ins:
            tx_ins += tx_in.__repr__() + '\n'
        tx_outs = ''
        for tx_out in self.tx_outs:
            tx_outs += tx_out.__repr__() + '\n'
        return 'tx: {}\nversion: {}\ntx_ins:\n{}\ntx_outs:\n{}\nlocktime: {}\n'.format(
            self.id(),
            self.version,
            tx_ins,
            tx_outs,
            self.locktime,
        )

    def id(self):
        '''Human-readable hexadecimal of the transaction hash'''
        return self.hash().hex()

    def hash(self):
        '''Binary hash of the legacy serialization'''
        return hash256(self.serialize_legacy())[::-1]

    @classmethod
    def parse(cls, s, testnet=False):
        '''Parses a transaction from stream'''
        # we can determine whether something is segwit or legacy by looking
        # at byte 5
        s.read(4)
        if s.read(1) == b'\x00':
            parse_method = cls.parse_segwit
        else:
            parse_method = cls.parse_legacy
        # reset the seek to the beginning so everything can go through
        s.seek(-5, 1)
        return parse_method(s, testnet=testnet)

    @classmethod
    def parse_legacy(cls, s, testnet=False):
        '''Takes a byte stream and parses a legacy transaction'''
        # s.read(n) will return n bytes
        # version has 4 bytes, little-endian, interpret as int
        version = little_endian_to_int(s.read(4))
        # num_inputs is a varint, use read_varint(s)
        num_inputs = read_varint(s)
        # each input needs parsing
        inputs = []
        for _ in range(num_inputs):
            inputs.append(TxIn.parse(s))
        # num_outputs is a varint, use read_varint(s)
        num_outputs = read_varint(s)
        # each output needs parsing
        outputs = []
        for _ in range(num_outputs):
            outputs.append(TxOut.parse(s))
        # locktime is 4 bytes, little-endian
        locktime = little_endian_to_int(s.read(4))
        # return an instance of the class (cls(...))
        return cls(version, inputs, outputs, locktime, testnet=testnet, segwit=False)

    @classmethod
    def parse_segwit(cls, s, testnet=False):
        '''Takes a byte stream and parses a segwit transaction'''
        # s.read(n) will return n bytes
        # version has 4 bytes, little-endian, interpret as int
        version = little_endian_to_int(s.read(4))
        # next two bytes need to be 0x00 and 0x01
        marker = s.read(2)
        if marker != b'\x00\x01':
            raise RuntimeError('Not a segwit transaction {}'.format(marker))
        # num_inputs is a varint, use read_varint(s)
        num_inputs = read_varint(s)
        # each input needs parsing
        inputs = []
        for _ in range(num_inputs):
            inputs.append(TxIn.parse(s))
        # num_outputs is a varint, use read_varint(s)
        num_outputs = read_varint(s)
        # each output needs parsing
        outputs = []
        for _ in range(num_outputs):
            outputs.append(TxOut.parse(s))
        # now parse the witness program
        for tx_in in inputs:
            num_items = read_varint(s)
            items = []
            for _ in range(num_items):
                items.append(read_varstr(s))
            tx_in.witness = items
        # locktime is 4 bytes, little-endian
        locktime = little_endian_to_int(s.read(4))
        # return an instance of the class (cls(...))
        return cls(version, inputs, outputs, locktime, testnet=testnet, segwit=True)

    def serialize(self):
        if self.segwit:
            return self.serialize_segwit()
        else:
            return self.serialize_legacy()

    def serialize_legacy(self):
        '''Returns the byte serialization of the transaction'''
        # serialize version (4 bytes, little endian)
        result = int_to_little_endian(self.version, 4)
        # encode_varint on the number of inputs
        result += encode_varint(len(self.tx_ins))
        # iterate inputs
        for tx_in in self.tx_ins:
            # serialize each input
            result += tx_in.serialize()
        # encode_varint on the number of outputs
        result += encode_varint(len(self.tx_outs))
        # iterate outputs
        for tx_out in self.tx_outs:
            # serialize each output
            result += tx_out.serialize()
        # serialize locktime (4 bytes, little endian)
        result += int_to_little_endian(self.locktime, 4)
        return result

    def serialize_segwit(self):
        '''Returns the byte serialization of the transaction'''
        # serialize version (4 bytes, little endian)
        result = int_to_little_endian(self.version, 4)
        # segwit marker '0001'
        result += b'\x00\x01'
        # encode_varint on the number of inputs
        result += encode_varint(len(self.tx_ins))
        # iterate inputs
        for tx_in in self.tx_ins:
            # serialize each input
            result += tx_in.serialize()
        # encode_varint on the number of inputs
        result += encode_varint(len(self.tx_outs))
        # iterate outputs
        for tx_out in self.tx_outs:
            # serialize each output
            result += tx_out.serialize()
        # add the witness data
        for tx_in in self.tx_ins:
            result += encode_varint(len(tx_in.witness))
            for item in tx_in.witness:
                if type(item) == int:
                    result += int_to_little_endian(item, 1)
                else:
                    result += encode_varstr(item)
        # serialize locktime (4 bytes, little endian)
        result += int_to_little_endian(self.locktime, 4)
        return result

    def fee(self):
        '''Returns the fee of this transaction in satoshi'''
        # initialize input sum and output sum
        input_sum, output_sum = 0, 0
        # iterate through inputs
        for tx_in in self.tx_ins:
            # for each input get the value and add to input sum
            input_sum += tx_in.value(self.testnet)
        # iterate through outputs
        for tx_out in self.tx_outs:
            # for each output get the amount and add to output sum
            output_sum += tx_out.amount
        # return input sum - output sum
        return input_sum - output_sum

    def sig_hash(self, input_index, redeem_script=None):
        '''Returns the integer representation of the hash that needs to get
        signed for index input_index'''
        # create a new set of tx_ins (alt_tx_ins)
        alt_tx_ins = []
        # iterate over self.tx_ins
        for tx_in in self.tx_ins:
            # create a new TxIn that has no script_sig and add to alt_tx_ins
            alt_tx_ins.append(TxIn(
                prev_tx=tx_in.prev_tx,
                prev_index=tx_in.prev_index,
                sequence=tx_in.sequence,
            ))
        # grab the input at the input_index
        signing_input = alt_tx_ins[input_index]
        # p2sh would require a redeem_script
        if redeem_script:
            # p2sh replaces the script_sig with the redeem_script
            signing_input.script_sig = redeem_script
        else:
            # the script_sig of the signing_input should be script_pubkey
            signing_input.script_sig = signing_input.script_pubkey(self.testnet)
        # create an alternate transaction with the modified tx_ins
        alt_tx = self.__class__(
            version=self.version,
            tx_ins=alt_tx_ins,
            tx_outs=self.tx_outs,
            locktime=self.locktime)
        # add the hash_type int 4 bytes, little endian
        result = alt_tx.serialize() + int_to_little_endian(SIGHASH_ALL, 4)
        # get the hash256 of the tx serialization
        LOGGER.info('result = {}'.format(result.hex()))
        s256 = hash256(result)
        LOGGER.info('s256 = {}'.format(s256.hex()))
        # convert this to a big-endian integer using int.from_bytes(x, 'big')
        return int.from_bytes(s256, 'big')

    def hash_prevouts(self):
        if self._hash_prevouts is None:
            all_prevouts = b''
            all_sequence = b''
            for tx_in in self.tx_ins:
                all_prevouts += tx_in.prev_tx[::-1] + int_to_little_endian(tx_in.prev_index, 4)
                all_sequence += int_to_little_endian(tx_in.sequence, 4)
            self._hash_prevouts = hash256(all_prevouts)
            self._hash_sequence = hash256(all_sequence)
        return self._hash_prevouts

    def hash_sequence(self):
        if self._hash_sequence is None:
            self.hash_prevouts()  # this should calculate self._hash_prevouts
        return self._hash_sequence

    def hash_outputs(self):
        if self._hash_outputs is None:
            all_outputs = b''
            for tx_out in self.tx_outs:
                all_outputs += tx_out.serialize()
            self._hash_outputs = hash256(all_outputs)
        return self._hash_outputs

    def sig_hash_bip143(self, input_index, redeem_script=None, witness_script=None):
        '''Returns the integer representation of the hash that needs to get
        signed for index input_index'''
        tx_in = self.tx_ins[input_index]
        # per BIP143 spec
        s = int_to_little_endian(self.version, 4)
        s += self.hash_prevouts() + self.hash_sequence()
        s += tx_in.prev_tx[::-1] + int_to_little_endian(tx_in.prev_index, 4)
        if witness_script:
            script_code = witness_script.serialize()
        elif redeem_script:
            script_code = p2pkh_script(redeem_script.commands[1]).serialize()
        else:
            script_code = p2pkh_script(tx_in.script_pubkey(self.testnet).commands[1]).serialize()
        s += script_code
        s += int_to_little_endian(tx_in.value(self.testnet), 8)
        s += int_to_little_endian(tx_in.sequence, 4)
        s += self.hash_outputs()
        s += int_to_little_endian(self.locktime, 4)
        s += int_to_little_endian(SIGHASH_ALL, 4)
        return int.from_bytes(hash256(s), 'big')

    def verify_input(self, input_index):
        '''Returns whether the input has a valid signature'''
        # get the relevant input
        tx_in = self.tx_ins[input_index]
        script_pubkey = tx_in.script_pubkey(testnet=self.testnet)
        # check to see if the script_pubkey is a p2sh
        if script_pubkey.is_p2sh_script_pubkey():
            # the last element has to be the redeem script to trigger
            command = tx_in.script_sig.commands[-1]
            raw_redeem = int_to_little_endian(len(command), 1) + command
            redeem_script = Script.parse(BytesIO(raw_redeem))
            if redeem_script.is_p2wpkh_script_pubkey():
                z = self.sig_hash_bip143(input_index, redeem_script)
                witness = tx_in.witness
            elif redeem_script.is_p2wsh_script_pubkey():
                command = tx_in.witness[-1]
                raw_witness = encode_varstr(command)
                witness_script = Script.parse(BytesIO(raw_witness))
                z = self.sig_hash_bip143(input_index, witness_script=witness_script)
                witness = tx_in.witness
            else:
                z = self.sig_hash(input_index, redeem_script)
                witness = None
        else:
            if script_pubkey.is_p2wpkh_script_pubkey():
                z = self.sig_hash_bip143(input_index)
                witness = tx_in.witness
            elif script_pubkey.is_p2wsh_script_pubkey():
                command = tx_in.witness[-1]
                raw_witness = encode_varstr(command)
                witness_script = Script.parse(BytesIO(raw_witness))
                z = self.sig_hash_bip143(input_index, witness_script=witness_script)
                witness = tx_in.witness
            else:
                z = self.sig_hash(input_index)
                LOGGER.info('z = '.format(hex(z)))
                witness = None
        # combine the current script_sig and the previous script_pubkey
        script = tx_in.script_sig + script_pubkey
        # now evaluate this script and see if it passes
        return script.evaluate(
            z, self.version, self.locktime, tx_in.sequence, witness,
            bip65=self.bip65, bip112=self.bip112,
        )

    def verify(self):
        '''Verify every input of this transaction'''
        for i in range(len(self.tx_ins)):
            if not self.verify_input(i):
                LOGGER.info('failed at input {}'.format(i))
                return False
        return True

    def sign_input_p2pkh(self, input_index, private_key):
        '''Signs the input using the private key'''
        # get the sig_hash (z)
        z = self.sig_hash(input_index)
        # get der signature of z from private key
        der = private_key.sign(z).der()
        # append the hash_type to der (use SIGHASH_ALL.to_bytes(1, 'big'))
        sig = der + SIGHASH_ALL.to_bytes(1, 'big')
        # calculate the sec
        sec = private_key.point.sec()
        # change input's script_sig to a new script with [sig, sec] as the commands
        self.tx_ins[input_index].script_sig = Script([sig, sec])
        # return whether sig is valid using self.verify_input
        return self.verify_input(input_index)

    def sign_input_p2sh_multisig(self, input_index, private_keys, redeem_script):
        '''Signs the input using the private key'''
        # get the sig_hash (z)
        z = self.sig_hash(input_index, redeem_script=redeem_script)
        # initialize the script_sig commands with a 0 (OP_CHECKMULTISIG bug)
        commands = [0]
        for private_key in private_keys:
            # get der signature of z from private key
            der = private_key.sign(z).der()
            # append the hash_type to der (use SIGHASH_ALL.to_bytes(1, 'big'))
            sig = der + SIGHASH_ALL.to_bytes(1, 'big')
            # add the signature to the commands
            commands.append(sig)
        # finally, add the redeem script to the commands array
        commands.append(redeem_script.raw_serialize())
        # change input's script_sig to the Script consisting of the commands array
        self.tx_ins[input_index].script_sig = Script(commands)
        # return whether sig is valid using self.verify_input
        return self.verify_input(input_index)

    def sign_input_p2wpkh(self, input_index, private_key):
        '''Signs the input using the private key'''
        # get the sig_hash (z)
        z = self.sig_hash_bip143(input_index)
        # calculate the signature
        der = private_key.sign(z).der()
        # append the hash_type to der (use SIGHASH_ALL.to_bytes(1, 'big'))
        sig = der + SIGHASH_ALL.to_bytes(1, 'big')
        # get the sec
        sec = private_key.point.sec()
        # get the input
        tx_in = self.tx_ins[input_index]
        tx_in.witness = [sig, sec]
        # return whether sig is valid using self.verify_input
        return self.verify_input(input_index)

    def sign_input_p2sh_p2wpkh(self, input_index, private_key):
        '''Signs the input using the private key'''
        redeem_script = Script([0, private_key.point.hash160()])
        # get the sig_hash (z)
        z = self.sig_hash_bip143(input_index, redeem_script=redeem_script)
        # calculate the signature
        der = private_key.sign(z).der()
        # append the hash_type to der (use SIGHASH_ALL.to_bytes(1, 'big'))
        sig = der + SIGHASH_ALL.to_bytes(1, 'big')
        # get the sec
        sec = private_key.point.sec()
        # finally get the redeem script
        redeem = redeem_script.raw_serialize()
        # get the input
        tx_in = self.tx_ins[input_index]
        # change input's script_sig to the Script consisting of the redeem script
        tx_in.script_sig = Script([redeem])
        tx_in.witness = [sig, sec]
        # return whether sig is valid using self.verify_input
        return self.verify_input(input_index)

    def sign_input_p2wsh_multisig(self, input_index, private_keys, witness_script):
        '''Signs the input using the private key'''
        # get the sig_hash (z)
        z = self.sig_hash_bip143(input_index, witness_script=witness_script)
        # initialize the witness items with a 0 (OP_CHECKMULTISIG bug)
        items = [0]
        for private_key in private_keys:
            # get der signature of z from private key
            der = private_key.sign(z).der()
            # append the hash_type to der (use SIGHASH_ALL.to_bytes(1, 'big'))
            sig = der + SIGHASH_ALL.to_bytes(1, 'big')
            # add the signature to the items
            items.append(sig)
        # finally, add the witness script to the items array
        items.append(witness_script.raw_serialize())
        # change input's script_sig to the Script consisting of the items array
        self.tx_ins[input_index].witness = items
        # return whether sig is valid using self.verify_input
        return self.verify_input(input_index)

    def sign_input_p2sh_p2wsh_multisig(self, input_index, private_keys, witness_script):
        '''Signs the input using the private key'''
        tx_in = self.tx_ins[input_index]
        # the redeem_script is the only element in the script_sig
        redeem_script = Script([0, witness_script.sha256()])
        redeem = redeem_script.raw_serialize()
        tx_in.script_sig = Script([redeem])
        # get the sig_hash (z)
        z = self.sig_hash_bip143(input_index, witness_script=witness_script)
        # initialize the witness items with a 0 (OP_CHECKMULTISIG bug)
        items = [0]
        for private_key in private_keys:
            # get der signature of z from private key
            der = private_key.sign(z).der()
            # append the hash_type to der (use SIGHASH_ALL.to_bytes(1, 'big'))
            sig = der + SIGHASH_ALL.to_bytes(1, 'big')
            # add the signature to the items
            items.append(sig)
        # finally, add the witness script to the items array
        items.append(witness_script.raw_serialize())
        # change input's script_sig to the Script consisting of the items array
        tx_in.witness = items
        # return whether sig is valid using self.verify_input
        return self.verify_input(input_index)

    def is_coinbase(self):
        '''Returns whether this transaction is a coinbase transaction or not'''
        # check that there is exactly 1 input
        if len(self.tx_ins) != 1:
            return False
        # grab the first input
        first_input = self.tx_ins[0]
        # check that first input prev_tx is b'\x00' * 32 bytes
        if first_input.prev_tx != b'\x00' * 32:
            return False
        # check that first input prev_index is 0xffffffff
        if first_input.prev_index != 0xffffffff:
            return False
        return True

    def coinbase_height(self):
        '''Returns the height of the block this coinbase transaction is in
        Returns None if this transaction is not a coinbase transaction
        '''
        # if this is NOT a coinbase transaction, return None
        if not self.is_coinbase():
            return None
        # grab the first input's script_sig
        script_sig = self.tx_ins[0].script_sig
        # get the first byte of the scriptsig, which is the length
        length = script_sig.coinbase[0]
        # get the next length bytes
        command = script_sig.coinbase[1:1 + length]
        # convert the first element from little endian to int
        return little_endian_to_int(command)


class TxIn:

    def __init__(self, prev_tx, prev_index, script_sig=None, sequence=0xffffffff):
        self.prev_tx = prev_tx
        self.prev_index = prev_index
        if script_sig is None:
            self.script_sig = Script([])
        else:
            self.script_sig = script_sig
        self.sequence = sequence

    def __repr__(self):
        return '{}:{}'.format(
            self.prev_tx.hex(),
            self.prev_index,
        )

    @classmethod
    def parse(cls, s):
        '''Takes a byte stream and parses the tx_input at the start
        return a TxIn object
        '''
        # s.read(n) will return n bytes
        # prev_tx is 32 bytes, little endian
        prev_tx = s.read(32)[::-1]
        # prev_index is 4 bytes, little endian, interpret as int
        prev_index = little_endian_to_int(s.read(4))
        # script_sig is a variable field (length followed by the data)
        # you can use Script.parse to get the actual script
        coinbase_mode = prev_tx == b'\x00' * 32 and prev_index == 0xffffffff
        script_sig = Script.parse(s, coinbase_mode)
        # sequence is 4 bytes, little-endian, interpret as int
        sequence = little_endian_to_int(s.read(4))
        # return an instance of the class (cls(...))
        return cls(prev_tx, prev_index, script_sig, sequence)

    def serialize(self):
        '''Returns the byte serialization of the transaction input'''
        # serialize prev_tx, little endian
        result = self.prev_tx[::-1]
        # serialize prev_index, 4 bytes, little endian
        result += int_to_little_endian(self.prev_index, 4)
        # serialize the script_sig
        result += self.script_sig.serialize()
        # serialize sequence, 4 bytes, little endian
        result += int_to_little_endian(self.sequence, 4)
        return result

    def fetch_tx(self, testnet=False):
        return TxStore.fetch(self.prev_tx.hex(), testnet=testnet)

    def value(self, testnet=False):
        '''Get the outpoint value by looking up the tx hash
        Returns the amount in satoshi
        '''
        # use self.fetch_tx to get the transaction
        tx = self.fetch_tx(testnet=testnet)
        # get the output at self.prev_index
        # return the amount property
        return tx.tx_outs[self.prev_index].amount

    def script_pubkey(self, testnet=False):
        '''Get the scriptPubKey by looking up the tx hash
        Returns a Script object
        '''
        # use self.fetch_tx to get the transaction
        tx = self.fetch_tx(testnet=testnet)
        # get the output at self.prev_index
        # return the script_pubkey property
        return tx.tx_outs[self.prev_index].script_pubkey


class TxOut:

    def __init__(self, amount, script_pubkey):
        self.amount = amount
        self.script_pubkey = script_pubkey

    def __repr__(self):
        return '{}:{}'.format(self.amount, self.script_pubkey)

    @classmethod
    def parse(cls, s):
        '''Takes a byte stream and parses the tx_output at the start
        return a TxOut object
        '''
        # s.read(n) will return n bytes
        # amount is 8 bytes, little endian, interpret as int
        amount = little_endian_to_int(s.read(8))
        # script_pubkey is a variable field (length followed by the data)
        # you can use Script.parse to get the actual script
        script_pubkey = Script.parse(s)
        # return an instance of the class (cls(...))
        return cls(amount, script_pubkey)

    def serialize(self):
        '''Returns the byte serialization of the transaction output'''
        # serialize amount, 8 bytes, little endian
        result = int_to_little_endian(self.amount, 8)
        # serialize the script_pubkey
        result += self.script_pubkey.serialize()
        return result


class TxTest(TestCase):
    cache_file = 'tx.cache'

    @classmethod
    def setUpClass(cls):
        # fill with data from storage
        TxStore.testnet_store = TxStore(
            testnet=True, filename='testing-txs.testnet')
        TxStore.mainnet_store = TxStore(
            testnet=False, filename='testing-txs.mainnet')
        # weird transactions
        lookup = TxStore.testnet_store.tx_lookup
        weird = (
            (
                'c5d4b73af6eed28798473b05d2b227edd4f285069629843e899b52c2d1c165b7',
                '36d56883f4434e7b6a9411ba78cc9be767ae829d5559c442633e5b1b5f91d1c4',
            ),
            (
                '74ea059a63c7ebddaee6805e1560b15c937d99a9ee9745412cbc6d2a0a5f5305',
                '14a05e4b170af131c94b08a8f51c482dc4ab4594ec4db31260a5f27721ab2a5e',
            ),
            (
                'e335562f7e297aadeed88e5954bc4eeb8dc00b31d829eedb232e39d672b0c009',
                'c50b64ace11c66c362e18fb310c9cf22d3da22e63f144e4b79b7046fbd0f778b',
            ),
        )
        for a, b in weird:
            lookup[bytes.fromhex(a)] = lookup[bytes.fromhex(b)]

    def test_parse_version(self):
        tx = TxStore.fetch('452c629d67e41baec3ac6f04fe744b4b9617f8f859c63b3002f8684e7a4fee03')
        self.assertEqual(tx.version, 1)

    def test_parse_inputs(self):
        tx = TxStore.fetch('452c629d67e41baec3ac6f04fe744b4b9617f8f859c63b3002f8684e7a4fee03')
        self.assertEqual(len(tx.tx_ins), 1)
        want = 'd1c789a9c60383bf715f3f6ad9d14b91fe55f3deb369fe5d9280cb1a01793f81'
        self.assertEqual(tx.tx_ins[0].prev_tx.hex(), want)
        self.assertEqual(tx.tx_ins[0].prev_index, 0)
        want = '6b483045022100ed81ff192e75a3fd2304004dcadb746fa5e24c5031ccfcf21320b0277457c98f02207a986d955c6e0cb35d446a89d3f56100f4d7f67801c31967743a9c8e10615bed01210349fc4e631e3624a545de3f89f5d8684c7b8138bd94bdd531d2e213bf016b278a'
        self.assertEqual(tx.tx_ins[0].script_sig.serialize().hex(), want)
        self.assertEqual(tx.tx_ins[0].sequence, 0xfffffffe)

    def test_parse_outputs(self):
        tx = TxStore.fetch('452c629d67e41baec3ac6f04fe744b4b9617f8f859c63b3002f8684e7a4fee03')
        self.assertEqual(len(tx.tx_outs), 2)
        want = 32454049
        self.assertEqual(tx.tx_outs[0].amount, want)
        want = '1976a914bc3b654dca7e56b04dca18f2566cdaf02e8d9ada88ac'
        self.assertEqual(tx.tx_outs[0].script_pubkey.serialize().hex(), want)
        want = 10011545
        self.assertEqual(tx.tx_outs[1].amount, want)
        want = '1976a9141c4bc762dd5423e332166702cb75f40df79fea1288ac'
        self.assertEqual(tx.tx_outs[1].script_pubkey.serialize().hex(), want)

    def test_parse_locktime(self):
        tx = TxStore.fetch('452c629d67e41baec3ac6f04fe744b4b9617f8f859c63b3002f8684e7a4fee03')
        self.assertEqual(tx.locktime, 410393)

    def test_parse(self):
        raw_tx = '01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff2b69d614f5f69bab704552e66eeaf720d07294ebe80ba37181a5df8c7fdaecac910878060b0a85543de9b224ffffffff0100f2052a01000000232102f3cedb3c71052860e6329e4fd7b1ad51220a21111f2bf4fec3691e6f52664a75ac00000000'
        tx = Tx.parse(BytesIO(bytes.fromhex(raw_tx)))
        self.assertEqual(tx.version, 1)

    def test_serialize(self):
        raw_tx = '0100000001813f79011acb80925dfe69b3def355fe914bd1d96a3f5f71bf8303c6a989c7d1000000006b483045022100ed81ff192e75a3fd2304004dcadb746fa5e24c5031ccfcf21320b0277457c98f02207a986d955c6e0cb35d446a89d3f56100f4d7f67801c31967743a9c8e10615bed01210349fc4e631e3624a545de3f89f5d8684c7b8138bd94bdd531d2e213bf016b278afeffffff02a135ef01000000001976a914bc3b654dca7e56b04dca18f2566cdaf02e8d9ada88ac99c39800000000001976a9141c4bc762dd5423e332166702cb75f40df79fea1288ac19430600'
        tx = TxStore.fetch('452c629d67e41baec3ac6f04fe744b4b9617f8f859c63b3002f8684e7a4fee03')
        self.assertEqual(tx.serialize().hex(), raw_tx)

    def test_input_value(self):
        tx_id = 'd1c789a9c60383bf715f3f6ad9d14b91fe55f3deb369fe5d9280cb1a01793f81'
        index = 0
        want = 42505594
        tx_in = TxIn(bytes.fromhex(tx_id), index)
        self.assertEqual(tx_in.value(), want)

    def test_input_pubkey(self):
        tx_id = 'd1c789a9c60383bf715f3f6ad9d14b91fe55f3deb369fe5d9280cb1a01793f81'
        index = 0
        tx_in = TxIn(bytes.fromhex(tx_id), index)
        want = '1976a914a802fc56c704ce87c42d7c92eb75e7896bdc41ae88ac'
        self.assertEqual(tx_in.script_pubkey().serialize().hex(), want)

    def test_fee(self):
        tx = TxStore.fetch('452c629d67e41baec3ac6f04fe744b4b9617f8f859c63b3002f8684e7a4fee03')
        self.assertEqual(tx.fee(), 40000)
        tx = TxStore.fetch('ee51510d7bbabe28052038d1deb10c03ec74f06a79e21913c6fcf48d56217c87')
        self.assertEqual(tx.fee(), 140500)

    def test_sig_hash(self):
        tx = TxStore.fetch('452c629d67e41baec3ac6f04fe744b4b9617f8f859c63b3002f8684e7a4fee03')
        want = int('27e0c5994dec7824e56dec6b2fcb342eb7cdb0d0957c2fce9882f715e85d81a6', 16)
        self.assertEqual(tx.sig_hash(0), want)

    def test_verify_p2pkh(self):
        tx = TxStore.fetch('452c629d67e41baec3ac6f04fe744b4b9617f8f859c63b3002f8684e7a4fee03')
        self.assertTrue(tx.verify())

    def test_verify_p2sh(self):
        tx = TxStore.fetch('46df1a9484d0a81d03ce0ee543ab6e1a23ed06175c104a178268fad381216c2b')
        self.assertTrue(tx.verify())

    def test_verify_p2wpkh(self):
        tx = TxStore.fetch('d869f854e1f8788bcff294cc83b280942a8c728de71eb709a2c29d10bfe21b7c', testnet=True)
        self.assertTrue(tx.verify())

    def test_verify_p2sh_p2wpkh(self):
        tx = TxStore.fetch('c586389e5e4b3acb9d6c8be1c19ae8ab2795397633176f5a6442a261bbdefc3a')
        self.assertTrue(tx.verify())

    def test_verify_p2wsh(self):
        tx = TxStore.fetch('78457666f82c28aa37b74b506745a7c7684dc7842a52a457b09f09446721e11c', testnet=True)
        self.assertTrue(tx.verify())

    def test_verify_p2sh_p2wsh(self):
        tx = TxStore.fetch('954f43dbb30ad8024981c07d1f5eb6c9fd461e2cf1760dd1283f052af746fc88', testnet=True)
        self.assertTrue(tx.verify())

    def test_verify_if(self):
        tx = TxStore.fetch('61ba3a8b40706931b72929628cf1a07d604f158c8350055725c664d544d00030', testnet=True)
        self.assertTrue(tx.verify())

    def test_verify_cltv(self):
        tx = TxStore.fetch('ca2c7347aa2fdff68052f026fa9a092448c2451f774ca53f3a2b05d74405addc', testnet=True)
        self.assertTrue(tx.verify())

    def test_verify_csv(self):
        tx = TxStore.fetch('d208b659eaca2640f732b07b11ea9800c1a0bb4ffdc03aaf82af76c1787570ac', testnet=True)
        self.assertTrue(tx.verify())

    def test_verify_csv_2(self):
        tx = TxStore.fetch('807d464fff227ce98cfb5f1292069e2793e99f21b0539a1729cc460af32add77', testnet=True)
        self.assertTrue(tx.verify())

    def test_verify_lightning_local_success(self):
        tx = TxStore.fetch('0191535bfda21f5dfec1c904775c5e2fbee8a985815c88d77258a0b42dba3526')
        self.assertTrue(tx.verify())

    def test_verify_lightning_local_penalty(self):
        tx = TxStore.fetch('0da5e5dba5e793d50820c2275dab74912b121c8b7e34ce32a9dbfd4567a9bf8e')
        self.assertTrue(tx.verify())

    def test_verify_lightning_sender_timeout(self):
        tx = TxStore.fetch('a16f6d78a58d31fe7459887adf5bd6b4dd95277ea375d250c700cde9fa908bdb')
        self.assertTrue(tx.verify())

    def test_verify_lightning_sender_preimage(self):
        tx = TxStore.fetch('89c744f0806a57a9b4634c320703cc941aaf272f290296373b709499064335e5')
        self.assertTrue(tx.verify())

    def test_verify_lightning_receiver_timeout(self):
        tx = TxStore.fetch('f9af9b93d66c7e5ee7dcbe0b53faa3d17aa6b9f4cc5b19f0985917b57d82c59a')
        self.assertTrue(tx.verify())

    def test_verify_lightning_receiver_preimage(self):
        tx = TxStore.fetch('36b1aff2ad0076be95b1ee1dc4036374998760c80c6583a6478a699e86658ac0')
        self.assertTrue(tx.verify())

    def test_verify_sha1_pinata(self):
        tx = TxStore.fetch('8d31992805518fd62daa3bdd2a5c4fd2cd3054c9b3dca1d78055e9528cff6adc')
        self.assertTrue(tx.verify())

    def test_verify_weird(self):
        tx_ids = (
            'efdf1b981d7bba9c941295c0dfc654c4b5e40d7b9744819dd4f78b8e149898e1',
            '9aa3a5a6d9b7d1ac9555be8e42596d06686cc5f76d259b06c560a207d310d5f5',
            'c5d4b73af6eed28798473b05d2b227edd4f285069629843e899b52c2d1c165b7',
            'e335562f7e297aadeed88e5954bc4eeb8dc00b31d829eedb232e39d672b0c009',
            'dc3aad51b4b9ea1ef40755a38b0b4d6e08c72d2ac5e95b8bebe9bd319b6aed7e',
        )
        for tx_id in tx_ids:
            tx = TxStore.fetch(tx_id, testnet=True)
            tx.bip112 = False
            tx.bip65 = False
            self.assertTrue(tx.verify())

    def test_verify_weird_2(self):
        import script
        before = script.DEBUG
        script.DEBUG = True
        tx = TxStore.fetch(
            '74ea059a63c7ebddaee6805e1560b15c937d99a9ee9745412cbc6d2a0a5f5305',
            testnet=True)
        tx.bip112 = False
        tx.bip65 = False
        for i in range(len(tx.tx_ins)):
            if i not in (29, 31):
                self.assertTrue(tx.verify_input(i), i)
        script.DEBUG = before

    def test_sign_input_p2pkh(self):
        private_key = PrivateKey(secret=8675309)
        tx_ins = []
        prev_tx = bytes.fromhex('0025bc3c0fa8b7eb55b9437fdbd016870d18e0df0ace7bc9864efc38414147c8')
        tx_ins.append(TxIn(prev_tx, 0))
        tx_outs = []
        h160 = decode_base58('mzx5YhAH9kNHtcN481u6WkjeHjYtVeKVh2')
        tx_outs.append(TxOut(amount=int(0.99 * 100000000), script_pubkey=p2pkh_script(h160)))
        h160 = decode_base58('mnrVtF8DWjMu839VW3rBfgYaAfKk8983Xf')
        tx_outs.append(TxOut(amount=int(0.1 * 100000000), script_pubkey=p2pkh_script(h160)))
        tx = Tx(1, tx_ins, tx_outs, 0, True)
        self.assertTrue(tx.sign_input_p2pkh(0, private_key))

    def test_is_coinbase(self):
        tx = TxStore.fetch('51bdce0f8a1edd5bc023fd4de42edb63478ca67fc8a37a6e533229c17d794d3f')
        self.assertTrue(tx.is_coinbase())

    def test_coinbase_height(self):
        tx = TxStore.fetch('51bdce0f8a1edd5bc023fd4de42edb63478ca67fc8a37a6e533229c17d794d3f')
        self.assertEqual(tx.coinbase_height(), 465879)
        tx = TxStore.fetch('452c629d67e41baec3ac6f04fe744b4b9617f8f859c63b3002f8684e7a4fee03')
        self.assertIsNone(tx.coinbase_height())

    def test_p2sh_multisig(self):
        secrets = (b'jimmy@programmingblockchain.com test1', b'jimmy@programmingblockchain.com test2')
        private_keys = [PrivateKey(little_endian_to_int(hash256(s))) for s in secrets]
        points = [p.point for p in private_keys]
        redeem_script = multisig_redeem_script(2, points)
        prev_tx = bytes.fromhex('770e48abf1051fe8df7d906d6a6589a3a6fe4da09edd5e4172ee04db3e88dfb8')
        prev_index = 0
        fee = int(100000000*0.001)
        tx_in = TxIn(prev_tx, prev_index)
        h160 = redeem_script.hash160()
        script_pubkey = p2sh_script(h160)
        amount = tx_in.value(testnet=True) - fee - 1000000
        tx_out_1 = TxOut(amount, script_pubkey)
        h160 = decode_base58('2N3a8NdfeA7SAurCGsd5k9AEYvbszipz3Jz')
        script_pubkey = p2sh_script(h160)
        tx_out_2 = TxOut(1000000, script_pubkey)
        t = Tx(1, [tx_in], [tx_out_1, tx_out_2], 0, testnet=True)
        t.sign_input_p2sh_multisig(0, private_keys, redeem_script)
        want = '0100000001b8df883edb04ee72415edd9ea04dfea6a389656a6d907ddfe81f05f1ab480e7700000000db004830450221009bb0421ba4193dcefffacc4f7e99491e524719fdb89dd438adcfd1de8f82298402202d605605365d9b8492953eddfcd158fc0ac728dab89269a720c5621e313c5f2601483045022100c619ed09b0f20e3b47f206f92fe1903c8ae6505088e67b3d2f69ddc3ac3207e002204ea256baab6e3543fa2b836917994e6f59e8aeb23d5ec213dc2279adb3e1a7e9014752210223136797cb0d7596cb5bd476102fe3aface2a06338e1afabffacf8c3cab4883c210385c865e61e275ba6fda4a3167180fc5a6b607150ff18797ee44737cd0d34507b52aeffffffff02f7dc69000000000017a91436b865d5b9664193ea1db43d159edf9edf9438028740420f000000000017a9147144796678ef9edc1a86745c2a01f8fb923ed6568700000000'
        self.assertEqual(t.serialize().hex(), want)

    def test_p2sh_p2wpkh(self):
        secret = b'jimmy@programmingblockchain.com test1'
        private_key = PrivateKey(little_endian_to_int(hash256(secret)))
        point = private_key.point
        real_h160 = hash160(point.sec())
        redeem_script = p2wpkh_script(real_h160)
        h160 = redeem_script.hash160()
        prev_tx = bytes.fromhex('e6add1b775d9877e6d7e3d2ddd8464fecf88c37149044d2f9bc46297f2294a3d')
        prev_index = 1
        fee = int(100000000*0.001)
        tx_in = TxIn(prev_tx, prev_index)
        witness = decode_bech32('tb1q3845h8hm5uqgjh7jkq4pkrftlrcgvjf442jh4z')
        h160 = witness[2:]
        script_pubkey = p2wpkh_script(h160)
        amount = tx_in.value(testnet=True) - fee
        tx_out = TxOut(amount, script_pubkey)
        t = Tx(1, [tx_in], [tx_out], 0, testnet=True)
        t.sign_input_p2sh_p2wpkh(0, private_key)
        want = '010000000001013d4a29f29762c49b2f4d044971c388cffe6484dd2d3d7e6d7e87d975b7d1ade6010000001716001489eb4b9efba700895fd2b02a1b0d2bf8f0864935ffffffff01a0bb0d000000000016001489eb4b9efba700895fd2b02a1b0d2bf8f0864935024830450221009af2dec92bc2101c84cf984e01561c9bdc2563091417c21f495605757831b90202203c203fd9edf0da344da46fca347e115089a525ba6a0a488b17f445fab3f7f29701210223136797cb0d7596cb5bd476102fe3aface2a06338e1afabffacf8c3cab4883c00000000'
        self.assertEqual(t.serialize_segwit().hex(), want)

    def test_p2wpkh(self):
        secret = b'jimmy@programmingblockchain.com test1'
        private_key = PrivateKey(little_endian_to_int(hash256(secret)))
        prev_tx = bytes.fromhex('15298dc29fccc3ce2f96126a606daa29a8f68fc5906ed859d23dfb517549aa6e')
        prev_index = 0
        fee = int(100000000*0.001)
        tx_in = TxIn(prev_tx, prev_index)
        amount = tx_in.value(testnet=True) - fee
        raw_witness = decode_bech32('tb1qevl98yey2nqnhnh5psn3h73zfl9yy5ae3ss4e79qungqa8y0eprsl8gle6')
        h256 = raw_witness[2:]
        script_pubkey = p2wsh_script(h256)
        tx_out = TxOut(amount, script_pubkey)
        t = Tx(1, [tx_in], [tx_out], 0, testnet=True)
        t.sign_input_p2wpkh(0, private_key)
        want = '010000000001016eaa497551fb3dd259d86e90c58ff6a829aa6d606a12962fcec3cc9fc28d29150000000000ffffffff0100350c0000000000220020cb3e53932454c13bcef40c271bfa224fca4253b98c215cf8a0e4d00e9c8fc847024730440220627d44b8eea048a45491c923647f397a7a15b412aa4d39d3a050a754bf3d1824022036cde64835589db899034b4a58757ec7fed7e120aa85ae40ff7eb625314e5d9f01210223136797cb0d7596cb5bd476102fe3aface2a06338e1afabffacf8c3cab4883c00000000'
        self.assertEqual(t.serialize_segwit().hex(), want)

    def test_p2wsh_multisig(self):
        secrets = (b'jimmy@programmingblockchain.com test1', b'jimmy@programmingblockchain.com test2')
        private_keys = [PrivateKey(little_endian_to_int(hash256(s))) for s in secrets]
        points = [p.point for p in private_keys]
        witness_script = multisig_redeem_script(2, points)
        prev_tx = bytes.fromhex('6cfee84dd0b659bd826071824bbb2a38454922624d0fea21200cf18f83526c88')
        prev_index = 0
        fee = int(100000000*0.001)
        tx_in = TxIn(prev_tx, prev_index)
        amount = tx_in.value(testnet=True) - fee
        h160 = decode_base58('2MuVPpBuS6evYsVeUJ85Z5Z6hokXGdtkYAw')
        script_pubkey = p2sh_script(h160)
        tx_out = TxOut(amount, script_pubkey)
        t = Tx(1, [tx_in], [tx_out], 0, testnet=True)
        t.sign_input_p2wsh_multisig(0, private_keys, witness_script)
        want = '01000000000101886c52838ff10c2021ea0f4d62224945382abb4b82716082bd59b6d04de8fe6c0000000000ffffffff0160ae0a000000000017a914189e46fe6452ece52a362cf162fead10c5f244028704004830450221009099d2ff28dc7c7752a6026e5c054c58de7f5ce02e8e1c8b33b015fc12d7da3e022006f8560ea3b35f3e8d44e791f96312245c00c5bb50f95754f031c2bb3de18cc101483045022100b264087806a4d12f28f3f45e0c6acbea8c3a6cef3dfcca48e250bd1677008643022043583e9dab7215466ce2a361dd33ac51e9317c574e26ab134608cc08dd40e3fb014752210223136797cb0d7596cb5bd476102fe3aface2a06338e1afabffacf8c3cab4883c210385c865e61e275ba6fda4a3167180fc5a6b607150ff18797ee44737cd0d34507b52ae00000000'
        self.assertEqual(t.serialize_segwit().hex(), want)

    def test_p2sh_p2wsh_multisig(self):
        secrets = (b'jimmy@programmingblockchain.com test1', b'jimmy@programmingblockchain.com test2')
        private_keys = [PrivateKey(little_endian_to_int(hash256(s))) for s in secrets]
        points = [p.point for p in private_keys]
        witness_script = multisig_redeem_script(2, points)
        prev_tx = bytes.fromhex('c93fb86b46aab846efba2d20ffae15c1993ca4231d5b5993a229ac54e5a4f8c1')
        prev_index = 0
        fee = int(100000000*0.001)
        tx_in = TxIn(prev_tx, prev_index)
        amount = tx_in.value(testnet=True) - fee
        h160 = decode_base58('2MxEZNps15dAnGX5XaVwZWgoDvjvsDE5XSx')
        script_pubkey = p2sh_script(h160)
        tx_out = TxOut(amount, script_pubkey)
        t = Tx(1, [tx_in], [tx_out], 0, testnet=True)
        t.sign_input_p2sh_p2wsh_multisig(0, private_keys, witness_script)
        want = '01000000000101c1f8a4e554ac29a293595b1d23a43c99c115aeff202dbaef46b8aa466bb83fc90000000023220020cb3e53932454c13bcef40c271bfa224fca4253b98c215cf8a0e4d00e9c8fc847ffffffff01c02709000000000017a91436b865d5b9664193ea1db43d159edf9edf94380287040047304402205581c0223cfc996e0db64e93b58862d059d9a8a35efd8311687f9eb2d42ff62502205f404afbcd05156a550b39048b151737a784bc4134598983294c5d013c56d44401483045022100f24f2e9967bec794ba52aca94b5c3c39ebd87932d38ecabd68dc51cc0e1c672d022047aaaaaf2cee39b280ebd371fa73797694ffae21e148a45b9c27cc526d0c97a9014752210223136797cb0d7596cb5bd476102fe3aface2a06338e1afabffacf8c3cab4883c210385c865e61e275ba6fda4a3167180fc5a6b607150ff18797ee44737cd0d34507b52ae00000000'
        self.assertEqual(t.serialize_segwit().hex(), want)
