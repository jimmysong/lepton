import socket
import time

from io import BytesIO
from logging import getLogger
from random import randint
from unittest import TestCase

from block import (
    LOWEST_BITS,
    Block,
)
from ecc import PrivateKey
from helper import (
    GOLOMB_M,
    GOLOMB_P,
    calculate_new_bits,
    decode_base58,
    decode_golomb,
    encode_varint,
    encode_varstr,
    hash256,
    hash_to_range,
    int_to_little_endian,
    little_endian_to_int,
    read_varint,
    read_varstr,
    unpack_bits,
)
from merkleblock import MerkleBlock
from script import p2pkh_script
from tx import Tx, TxIn, TxOut


LOGGER = getLogger(__name__)

TX_DATA_TYPE = 1
BLOCK_DATA_TYPE = 2
FILTERED_BLOCK_DATA_TYPE = 3
COMPACT_BLOCK_DATA_TYPE = 4
WITNESS_TX_DATA_TYPE = (1 << 30) + TX_DATA_TYPE
WITNESS_BLOCK_DATA_TYPE = (1 << 30) + BLOCK_DATA_TYPE

NETWORK_MAGIC = b'\xf9\xbe\xb4\xd9'
TESTNET_NETWORK_MAGIC = b'\x0b\x11\x09\x07'

BASIC_FILTER_TYPE = 0


class NetworkEnvelope:

    def __init__(self, command, payload, testnet=False):
        self.command = command
        self.payload = payload
        if testnet:
            self.magic = TESTNET_NETWORK_MAGIC
        else:
            self.magic = NETWORK_MAGIC

    def __repr__(self):
        return '{}: {}'.format(
            self.command.decode('ascii'),
            self.payload.hex(),
        )

    @classmethod
    def parse(cls, s, testnet=False):
        '''Takes a stream and creates a NetworkEnvelope'''
        # check the network magic
        print(s)
        magic = s.read(4)
        if magic == b'':
            raise RuntimeError('Connection reset!')
        if testnet:
            expected_magic = TESTNET_NETWORK_MAGIC
        else:
            expected_magic = NETWORK_MAGIC
        if magic != expected_magic:
            raise RuntimeError('magic is not right {} vs {}'.format(magic.hex(), expected_magic.hex()))
        # command 12 bytes
        command = s.read(12)
        # strip the trailing 0's
        command = command.strip(b'\x00')
        # payload length 4 bytes, little endian
        payload_length = little_endian_to_int(s.read(4))
        # checksum 4 bytes, first four of hash256 of payload
        checksum = s.read(4)
        # payload is of length payload_length
        payload = s.read(payload_length)
        # verify checksum
        calculated_checksum = hash256(payload)[:4]
        if calculated_checksum != checksum:
            raise RuntimeError('checksum does not match')
        # return an instance of the class
        return cls(command, payload, testnet=testnet)

    def serialize(self):
        '''Returns the byte serialization of the entire network message'''
        # add the network magic
        result = self.magic
        # command 12 bytes
        # fill with 0's
        result += self.command + b'\x00' * (12 - len(self.command))
        # payload length 4 bytes, little endian
        result += int_to_little_endian(len(self.payload), 4)
        # checksum 4 bytes, first four of hash256 of payload
        result += hash256(self.payload)[:4]
        # payload
        result += self.payload
        return result

    def stream(self):
        '''Returns a stream for parsing the payload'''
        return BytesIO(self.payload)


class NetworkEnvelopeTest(TestCase):

    def test_parse(self):
        msg = bytes.fromhex('f9beb4d976657261636b000000000000000000005df6e0e2')
        stream = BytesIO(msg)
        envelope = NetworkEnvelope.parse(stream)
        self.assertEqual(envelope.command, b'verack')
        self.assertEqual(envelope.payload, b'')
        msg = bytes.fromhex('f9beb4d976657273696f6e0000000000650000005f1a69d2721101000100000000000000bc8f5e5400000000010000000000000000000000000000000000ffffc61b6409208d010000000000000000000000000000000000ffffcb0071c0208d128035cbc97953f80f2f5361746f7368693a302e392e332fcf05050001')
        stream = BytesIO(msg)
        envelope = NetworkEnvelope.parse(stream)
        self.assertEqual(envelope.command, b'version')
        self.assertEqual(envelope.payload, msg[24:])
        self.assertEqual(envelope.__repr__()[:9], 'version: ')
        with self.assertRaises(RuntimeError):
            s = BytesIO(b'')
            NetworkEnvelope.parse(s)
        with self.assertRaises(RuntimeError):
            s = BytesIO(b'abcd')
            NetworkEnvelope.parse(s)
        with self.assertRaises(RuntimeError):
            s = BytesIO(msg[:-1] + b'\x00')
            NetworkEnvelope.parse(s)

    def test_serialize(self):
        msg = bytes.fromhex('f9beb4d976657261636b000000000000000000005df6e0e2')
        stream = BytesIO(msg)
        envelope = NetworkEnvelope.parse(stream)
        self.assertEqual(envelope.serialize(), msg)
        msg = bytes.fromhex('f9beb4d976657273696f6e0000000000650000005f1a69d2721101000100000000000000bc8f5e5400000000010000000000000000000000000000000000ffffc61b6409208d010000000000000000000000000000000000ffffcb0071c0208d128035cbc97953f80f2f5361746f7368693a302e392e332fcf05050001')
        stream = BytesIO(msg)
        envelope = NetworkEnvelope.parse(stream)
        self.assertEqual(envelope.serialize(), msg)


class VersionMessage:
    command = b'version'

    def __init__(self, version=70015, services=0, timestamp=None,
                 receiver_services=0,
                 receiver_ip=b'\x00\x00\x00\x00', receiver_port=8333,
                 sender_services=0,
                 sender_ip=b'\x00\x00\x00\x00', sender_port=8333,
                 nonce=None, user_agent=b'/programmingbitcoin:0.1/',
                 latest_block=0, relay=True):
        self.version = version
        self.services = services
        if timestamp is None:
            self.timestamp = int(time.time())
        else:
            self.timestamp = timestamp
        self.receiver_services = receiver_services
        self.receiver_ip = receiver_ip
        self.receiver_port = receiver_port
        self.sender_services = sender_services
        self.sender_ip = sender_ip
        self.sender_port = sender_port
        if nonce is None:
            self.nonce = int_to_little_endian(randint(0, 2**64), 8)
        else:
            self.nonce = nonce
        self.user_agent = user_agent
        self.latest_block = latest_block
        self.relay = relay

    @classmethod
    def parse(cls, s):
        version = little_endian_to_int(s.read(4))
        services = little_endian_to_int(s.read(8))
        timestamp = little_endian_to_int(s.read(8))
        receiver_services = little_endian_to_int(s.read(8))
        receiver_ip = s.read(16)[-4:]
        receiver_port = little_endian_to_int(s.read(2))
        sender_services = little_endian_to_int(s.read(8))
        sender_ip = s.read(16)[-4:]
        sender_port = little_endian_to_int(s.read(2))
        nonce = s.read(8)
        user_agent = read_varstr(s)
        latest_block = little_endian_to_int(s.read(4))
        relay = s.read(1) == b'\x01'
        return cls(version, services, timestamp, receiver_services,
                   receiver_ip, receiver_port, sender_services, sender_ip,
                   sender_port, nonce, user_agent, latest_block, relay)

    def serialize(self):
        '''Serialize this message to send over the network'''
        # version is 4 bytes little endian
        result = int_to_little_endian(self.version, 4)
        # services is 8 bytes little endian
        result += int_to_little_endian(self.services, 8)
        # timestamp is 8 bytes little endian
        result += int_to_little_endian(self.timestamp, 8)
        # receiver services is 8 bytes little endian
        result += int_to_little_endian(self.receiver_services, 8)
        # IPV4 is 10 00 bytes and 2 ff bytes then receiver ip
        result += b'\x00' * 10 + b'\xff\xff' + self.receiver_ip
        # receiver port is 2 bytes, little endian should be 0
        result += int_to_little_endian(self.receiver_port, 2)
        # sender services is 8 bytes little endian
        result += int_to_little_endian(self.sender_services, 8)
        # IPV4 is 10 00 bytes and 2 ff bytes then sender ip
        result += b'\x00' * 10 + b'\xff\xff' + self.sender_ip
        # sender port is 2 bytes, little endian should be 0
        result += int_to_little_endian(self.sender_port, 2)
        # nonce should be 8 bytes
        result += self.nonce
        # useragent is a variable string
        result += encode_varstr(self.user_agent)
        # latest block is 4 bytes little endian
        result += int_to_little_endian(self.latest_block, 4)
        # relay is 00 if false, 01 if true
        if self.relay:
            result += b'\x01'
        else:
            result += b'\x00'
        return result


class VersionMessageTest(TestCase):

    def test_serialize(self):
        v = VersionMessage(timestamp=0, nonce=b'\x00' * 8)
        self.assertEqual(v.serialize().hex(), '7f11010000000000000000000000000000000000000000000000000000000000000000000000ffff000000008d20000000000000000000000000000000000000ffff000000008d200000000000000000182f70726f6772616d6d696e67626974636f696e3a302e312f0000000001')
        v = VersionMessage(timestamp=0, nonce=b'\x00' * 8, relay=False)
        self.assertEqual(v.serialize().hex(), '7f11010000000000000000000000000000000000000000000000000000000000000000000000ffff000000008d20000000000000000000000000000000000000ffff000000008d200000000000000000182f70726f6772616d6d696e67626974636f696e3a302e312f0000000000')


class VerAckMessage:
    command = b'verack'

    def __init__(self):
        pass

    @classmethod
    def parse(cls, s):
        return cls()

    def serialize(self):
        return b''


class PingMessage:
    command = b'ping'

    def __init__(self, nonce):
        self.nonce = nonce

    @classmethod
    def parse(cls, s):
        nonce = s.read(8)
        return cls(nonce)

    def serialize(self):
        return self.nonce


class PongMessage:
    command = b'pong'

    def __init__(self, nonce):
        self.nonce = nonce

    @classmethod
    def parse(cls, s):
        nonce = s.read(8)
        return cls(nonce)

    def serialize(self):
        return self.nonce


class PingPongTest(TestCase):

    def test_ping_pong(self):
        ping = PingMessage(b'\x00' * 8)
        stream = BytesIO(ping.serialize())
        computed = PingMessage.parse(stream)
        self.assertEqual(ping.nonce, computed.nonce)
        pong = PongMessage(b'\x00' * 8)
        stream = BytesIO(pong.serialize())
        computed = PongMessage.parse(stream)
        self.assertEqual(pong.nonce, computed.nonce)

class GetHeadersMessage:
    command = b'getheaders'

    def __init__(self, version=70015, num_hashes=1, start_block=None, end_block=None):
        self.version = version
        self.num_hashes = num_hashes
        if start_block is None:
            raise RuntimeError('a start block is required')
        self.start_block = start_block
        if end_block is None:
            self.end_block = b'\x00' * 32
        else:
            self.end_block = end_block

    def serialize(self):
        '''Serialize this message to send over the network'''
        # protocol version is 4 bytes little-endian
        result = int_to_little_endian(self.version, 4)
        # number of hashes is a varint
        result += encode_varint(self.num_hashes)
        # start block is in little-endian
        result += self.start_block[::-1]
        # end block is also in little-endian
        result += self.end_block[::-1]
        return result


class GetHeadersMessageTest(TestCase):

    def test_serialize(self):
        block_hex = '0000000000000000001237f46acddf58578a37e213d2a6edc4884a2fcad05ba3'
        block = bytes.fromhex(block_hex)
        gh = GetHeadersMessage(start_block=block)
        self.assertEqual(gh.serialize().hex(), '7f11010001a35bd0ca2f4a88c4eda6d213e2378a5758dfcd6af437120000000000000000000000000000000000000000000000000000000000000000000000000000000000')
        gh = GetHeadersMessage(start_block=block, end_block=block)
        self.assertEqual(gh.serialize().hex(), '7f11010001a35bd0ca2f4a88c4eda6d213e2378a5758dfcd6af43712000000000000000000a35bd0ca2f4a88c4eda6d213e2378a5758dfcd6af43712000000000000000000')
        with self.assertRaises(RuntimeError):
            GetHeadersMessage()


class HeadersMessage:
    command = b'headers'

    def __init__(self, blocks):
        self.blocks = blocks

    @classmethod
    def parse(cls, stream):
        # number of headers is in a varint
        num_headers = read_varint(stream)
        # initialize the blocks array
        blocks = []
        # loop through number of headers times
        for _ in range(num_headers):
            # add a block to the blocks array by parsing the stream
            blocks.append(Block.parse(stream))
        # return a class instance
        return cls(blocks)


class HeadersMessageTest(TestCase):

    def test_parse(self):
        hex_msg = '0200000020df3b053dc46f162a9b00c7f0d5124e2676d47bbe7c5d0793a500000000000000ef445fef2ed495c275892206ca533e7411907971013ab83e3b47bd0d692d14d4dc7c835b67d8001ac157e670000000002030eb2540c41025690160a1014c577061596e32e426b712c7ca00000000000000768b89f07044e6130ead292a3f51951adbd2202df447d98789339937fd006bd44880835b67d8001ade09204600'
        stream = BytesIO(bytes.fromhex(hex_msg))
        headers = HeadersMessage.parse(stream)
        self.assertEqual(len(headers.blocks), 2)
        for b in headers.blocks:
            self.assertEqual(b.__class__, Block)


class GetDataMessage:
    command = b'getdata'

    def __init__(self):
        self.data = []

    def add(self, data_type, identifier):
        self.data.append((data_type, identifier))

    @classmethod
    def parse(cls, s):
        num_items = read_varint(s)
        result = cls()
        for _ in range(num_items):
            data_type = little_endian_to_int(s.read(4))
            identifier = s.read(32)[::-1]
            result.add(data_type, identifier)
        return result
        
    def serialize(self):
        # start with the number of items as a varint
        result = encode_varint(len(self.data))
        # loop through each tuple (data_type, identifier) in self.data
        for data_type, identifier in self.data:
            # data type is 4 bytes Little-Endian
            result += int_to_little_endian(data_type, 4)
            # identifier needs to be in Little-Endian
            result += identifier[::-1]
        return result


class InvMessage(GetDataMessage):
    command = b'inv'
    

class GetDataMessageTest(TestCase):

    def test_serialize(self):
        hex_msg = '020300000030eb2540c41025690160a1014c577061596e32e426b712c7ca00000000000000030000001049847939585b0652fba793661c361223446b6fc41089b8be00000000000000'
        getdata = GetDataMessage()
        block1 = bytes.fromhex('00000000000000cac712b726e4326e596170574c01a16001692510c44025eb30')
        getdata.add(FILTERED_BLOCK_DATA_TYPE, block1)
        block2 = bytes.fromhex('00000000000000beb88910c46f6b442312361c6693a7fb52065b583979844910')
        getdata.add(FILTERED_BLOCK_DATA_TYPE, block2)
        self.assertEqual(getdata.serialize().hex(), hex_msg)
        getdata2 = GetDataMessage.parse(BytesIO(bytes.fromhex(hex_msg)))
        self.assertEqual(getdata2.serialize().hex(), hex_msg)


class GetCFiltersMessage:
    command = b'getcfilters'

    def __init__(self, filter_type=BASIC_FILTER_TYPE, start_height=1, stop_hash=None):
        self.filter_type = filter_type
        self.start_height = start_height
        if stop_hash is None:
            raise RuntimeError
        self.stop_hash = stop_hash

    def serialize(self):
        result = self.filter_type.to_bytes(1, 'big')
        result += int_to_little_endian(self.start_height, 4)
        result += self.stop_hash[::-1]
        return result


class CFilterMessage:
    command = b'cfilter'

    def __init__(self, filter_type, block_hash, filter_bytes, hashes):
        self.filter_type = filter_type
        self.block_hash = block_hash
        self.filter_bytes = filter_bytes
        self.hashes = hashes
        self.f = len(self.hashes) * GOLOMB_M
        self.key = self.block_hash[::-1][:16]

    @classmethod
    def parse(cls, s):
        filter_type = s.read(1)[0]
        block_hash = s.read(32)[::-1]
        num_bytes = read_varint(s)
        filter_bytes = s.read(num_bytes)
        substream = BytesIO(filter_bytes)
        n = read_varint(substream)
        bits = unpack_bits(substream.read())
        hashes = set()
        current = 0
        for _ in range(n):
            delta = decode_golomb(bits, GOLOMB_P)
            current += delta
            hashes.add(current)
        return cls(filter_type, block_hash, filter_bytes, hashes)

    def hash(self, raw_script_pubkey):
        return hash_to_range(self.key, raw_script_pubkey, self.f)

    def __contains__(self, raw_script_pubkey):
        if type(raw_script_pubkey) == bytes:
            return self.hash(raw_script_pubkey) in self.hashes
        else:
            for r in raw_script_pubkey:
                if self.hash(r) in self.hashes:
                    return True
            return False


class CFilterTest(TestCase):

    def test_cfilter(self):
        stop_hash = bytes.fromhex('000000006f27ddfe1dd680044a34548f41bed47eba9e6f0b310da21423bc5f33')
        getcfilters = GetCFiltersMessage(stop_hash=stop_hash)
        expected = b'\x00\x01\x00\x00\x00' + stop_hash[::-1]
        self.assertEqual(getcfilters.serialize(), expected)
        expected = b'\x00' + stop_hash[::-1] + b'\x09' + bytes.fromhex('0385acb4f0fe889ef0')
        cfilter = CFilterMessage.parse(BytesIO(expected))
        self.assertEqual(cfilter.filter_type, 0)
        self.assertEqual(cfilter.block_hash, stop_hash)
        self.assertEqual(cfilter.hashes, {1341840, 1483084, 570774})
        self.assertEqual(cfilter.hash(b'\x00'), 1322199)
        included = bytes.fromhex('002027a5000c7917f785d8fc6e5a55adfca8717ecb973ebb7743849ff956d896a7ed')
        self.assertTrue([included] in cfilter)
        self.assertFalse([b'\x00'] in cfilter)
        with self.assertRaises(RuntimeError):
            GetCFiltersMessage()


class GetCFHeadersMessage:
    command = b'getcfheaders'

    def __init__(self, filter_type=BASIC_FILTER_TYPE, start_height=0, stop_hash=None):
        self.filter_type = filter_type
        self.start_height = start_height
        if stop_hash is None:
            raise RuntimeError
        self.stop_hash = stop_hash

    def serialize(self):
        result = self.filter_type.to_bytes(1, 'big')
        result += int_to_little_endian(self.start_height, 4)
        result += self.stop_hash[::-1]
        return result


class CFHeadersMessage:
    command = b'cfheaders'

    def __init__(self, filter_type, stop_hash, previous_filter_header, filter_hashes):
        self.filter_type = filter_type
        self.stop_hash = stop_hash
        self.previous_filter_header = previous_filter_header
        self.filter_hashes = filter_hashes

    @classmethod
    def parse(cls, s):
        filter_type = s.read(1)[0]
        stop_hash = s.read(32)[::-1]
        previous_filter_header = s.read(32)[::-1]
        filter_hashes_length = read_varint(s)
        filter_hashes = []
        for _ in range(filter_hashes_length):
            filter_hashes.append(s.read(32)[::-1])
        return cls(filter_type, stop_hash, previous_filter_header, filter_hashes)


class CFHeaderTest(TestCase):

    def test_cfheader(self):
        stop_hash = bytes.fromhex('000000006f27ddfe1dd680044a34548f41bed47eba9e6f0b310da21423bc5f33')
        getcfheaders = GetCFHeadersMessage(stop_hash=stop_hash)
        self.assertEqual(getcfheaders.serialize(), b'\x00\x00\x00\x00\x00' + stop_hash[::-1])
        hash2 = b'\x00' * 32
        stream = BytesIO(bytes.fromhex('00335fbc2314a20d310b6f9eba7ed4be418f54344a0480d61dfedd276f000000000000000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000000'))
        cfheaders = CFHeadersMessage.parse(stream)
        self.assertEqual(cfheaders.filter_type, 0)
        self.assertEqual(cfheaders.stop_hash, stop_hash)
        self.assertEqual(cfheaders.previous_filter_header, hash2)
        self.assertEqual(cfheaders.filter_hashes, [hash2])
        with self.assertRaises(RuntimeError):
            GetCFHeadersMessage()


class GetCFCheckPointMessage:
    command = b'getcfcheckpt'

    def __init__(self, filter_type=BASIC_FILTER_TYPE, stop_hash=None):
        self.filter_type = filter_type
        if stop_hash is None:
            raise RuntimeError('Need a stop hash')
        self.stop_hash = stop_hash

    def serialize(self):
        result = self.filter_type.to_bytes(1, 'big')
        result += self.stop_hash[::-1]
        return result


class CFCheckPointMessage:
    command = b'cfcheckpt'

    def __init__(self, filter_type, stop_hash, filter_headers):
        self.filter_type = filter_type
        self.stop_hash = stop_hash
        self.filter_headers = filter_headers

    @classmethod
    def parse(cls, s):
        filter_type = s.read(1)[0]
        stop_hash = s.read(32)[::-1]
        filter_headers_length = read_varint(s)
        filter_headers = []
        for _ in range(filter_headers_length):
            filter_headers.append(s.read(32)[::-1])
        return cls(filter_type, stop_hash, filter_headers)


class CFCheckPointTest(TestCase):

    def test_cfcheckpoint(self):
        stop_hash = bytes.fromhex('000000006f27ddfe1dd680044a34548f41bed47eba9e6f0b310da21423bc5f33')
        getcfcheckpoints = GetCFCheckPointMessage(stop_hash=stop_hash)
        self.assertEqual(getcfcheckpoints.serialize(), b'\x00' + stop_hash[::-1])
        hash2 = b'\x00' * 32
        stream = BytesIO(bytes.fromhex('00335fbc2314a20d310b6f9eba7ed4be418f54344a0480d61dfedd276f00000000010000000000000000000000000000000000000000000000000000000000000000000000'))
        cfcheckpoints = CFCheckPointMessage.parse(stream)
        self.assertEqual(cfcheckpoints.filter_type, 0)
        self.assertEqual(cfcheckpoints.stop_hash, stop_hash)
        self.assertEqual(cfcheckpoints.filter_headers, [hash2])
        with self.assertRaises(RuntimeError):
            GetCFCheckPointMessage()


class RejectMessage:
    command = b'reject'

    def __init__(self, message, code, reason):
        self.message = message
        self.code = code
        self.reason = reason

    def __repr__(self):
        return '{}\n{}\n'.format(
            self.message.decode('ascii'), self.reason.decode('ascii'))

    @classmethod
    def parse(cls, s):
        message = read_varstr(s)
        code = s.read(1)
        reason = read_varstr(s)
        return cls(message, code, reason)


class RejectMessageTest(TestCase):

    def test_parse(self):
        s = BytesIO(bytes.fromhex('09736f6d657468696e670109736f6d657468696e67'))
        rm = RejectMessage.parse(s)
        self.assertEqual(rm.message, b'something')
        self.assertEqual(rm.code, b'\x01')
        self.assertEqual(rm.reason, b'something')
        self.assertTrue('something' in rm.__repr__())


class NotFoundMessage:
    command = b'notfound'

    def __init__(self, data):
        self.data = data

    def __repr__(self):
        result = ''
        for item in self.data:
            result += '\n' + item[1].hex()
        return result

    @classmethod
    def parse(cls, s):
        num_items = read_varint(s)
        data = []
        for _ in range(num_items):
            item_type = little_endian_to_int(s.read(4))
            h = s.read(32)[::-1]
            data.append((item_type, h))
        return cls(data)


class NotFoundMessageTest(TestCase):

    def test_parse(self):
        s = BytesIO(bytes.fromhex('01010000000000000000000000000000000000000000000000000000000000000000000000'))
        nf = NotFoundMessage.parse(s)
        self.assertEqual(len(nf.data), 1)
        self.assertEqual(nf.data[0][0], 1)
        self.assertEqual(nf.data[0][1], b'\x00' * 32)
        self.assertTrue('0' * 64 in nf.__repr__())
    

class GenericMessage:
    def __init__(self, command, payload):
        self.command = command
        self.payload = payload

    def serialize(self):
        return self.payload


class SimpleNode:

    def __init__(self, host, port=None, testnet=False, logging=False, latest_block=0):
        if port is None:
            if testnet:
                port = 18333
            else:
                port = 8333
        self.testnet = testnet
        self.logging = logging
        # connect to socket
        self.host = host
        self.port = port
        self.tmp = open('tmp', 'wb')
        self.latest_block = latest_block
        LOGGER.info('initiating connection')
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.connect()

    def connect(self):
        self.socket.connect((self.host, self.port))
        self.stream = self.socket.makefile('rb', None)
        self.handshake()

    def handshake(self):
        '''Do a handshake with the other node.
        Handshake is sending a version message and getting a verack back.'''
        # create a version message signaling segwit and compact filters
        services = (1 << 3) | (1 << 6)
        version = VersionMessage(services=services, receiver_services=services,
                                 sender_services=services)
        # send the command
        self.send(version)
        # wait for a verack message
        self.wait_for(VerAckMessage)

    def send(self, message):
        '''Send a message to the connected node'''
        # create a network envelope
        envelope = NetworkEnvelope(
            message.command, message.serialize(), testnet=self.testnet)
        if self.logging:
            LOGGER.info('sending: {}'.format(envelope))
        # send the serialized envelope over the socket using sendall
        self.socket.sendall(envelope.serialize())

    def read(self):
        '''Read a message from the socket'''
        envelope = NetworkEnvelope.parse(self.stream, testnet=self.testnet)
        self.tmp.write(envelope.serialize())
        if self.logging:
            LOGGER.info('receiving: {}'.format(envelope))
        return envelope

    def wait_for(self, *message_classes):
        '''Wait for one of the messages in the list'''
        # initialize the command we have, which should be None
        command = None
        command_to_class = {m.command: m for m in message_classes}
        # loop until the command is in the commands we want
        while command not in command_to_class.keys():
            # get the next network message
            envelope = self.read()
            # set the command to be evaluated
            command = envelope.command
            # we know how to respond to version and ping, handle that here
            if command == VersionMessage.command:
                version = VersionMessage.parse(envelope.stream())
                self.latest_block = version.latest_block
                # send verack
                self.send(VerAckMessage())
            elif command == PingMessage.command:
                # send pong
                self.send(PongMessage(envelope.payload))
        # return the envelope parsed as a member of the right message class
        return command_to_class[command].parse(envelope.stream())

    def get_items(self, hashes, data_type, received_class):
        getdata = GetDataMessage()
        for h in hashes:
            getdata.add(data_type, h)
        self.send(getdata)
        for h in hashes:
            message = self.wait_for(received_class, NotFoundMessage)
            if message.command == NotFoundMessage.command:
                yield None, None
            else:
                yield h, message

    def get_blocks(self, hashes):
        return self.get_items(hashes, BLOCK_DATA_TYPE, Block)

    def get_filtered_block_txs(self, hashes):
        getdata = GetDataMessage()
        for h in hashes:
            getdata.add(FILTERED_BLOCK_DATA_TYPE, h)
        self.send(getdata)
        txs = []
        for h in hashes:
            mb = self.wait_for(MerkleBlock)
            if mb.header.hash() != h:
                raise RuntimeError('unexpected block at {}'.format(h.hex))
            valid, proved_txs = mb.check_validity()
            if not valid:
                raise RuntimeError('invalid block at {}'.format(h.hex))
            for h in proved_txs:
                yield h[::-1], self.wait_for(Tx)

    def send_tx(self, tx_obj):
        print(tx_obj.serialize().hex())
        if tx_obj.segwit:
            return self.send_tx_segwit(tx_obj)
        else:
            return self.send_tx_legacy(tx_obj)

    def send_tx_legacy(self, tx_obj):
        self.send(tx_obj)
        return tx_obj.id()

    def send_tx_segwit(self, tx_obj):
        # send an inv message with out tx
        inv = InvMessage()
        tx_hash = tx_obj.hash()
        inv.add(TX_DATA_TYPE, tx_hash)
        self.send(inv)
        # wait for a GetDataMessage
        getdata = self.wait_for(GetDataMessage)
        for data_type, identifier in getdata.data:
            if identifier == tx_hash and data_type == WITNESS_TX_DATA_TYPE:
                LOGGER.info('sending tx: {}'.format(tx_obj.id()))
                self.send(tx_obj)
                return tx_obj.id()


class SimpleNodeTest(TestCase):

    def test_get_blocks(self):
        node = SimpleNode('testnet.programmingbitcoin.com', testnet=True, logging=True)
        h = '00000000000000ee40c596528d9daadd030de8c538b812cf271cbebc47f9cfb5'
        for block_hash, b in node.get_blocks([bytes.fromhex(h)]):
            self.assertEqual(block_hash, b.hash())


class IntegrationTest(TestCase):

    @classmethod
    def setUpClass(cls):
        # fill with data from storage
        from tx import TxStore
        TxStore.testnet_store = TxStore(
            testnet=True, filename='testing-txs.testnet')

    def test_broadcast(self):
        from bloomfilter import BloomFilter
        last_block_hex = '00000000000000a03f9432ac63813c6710bfe41712ac5ef6faab093fe2917636'
        secret = little_endian_to_int(hash256(b'Jimmy Song'))
        private_key = PrivateKey(secret=secret)
        h160 = private_key.point.hash160()
        addr = private_key.point.address(testnet=True)
        target_address = 'mwJn1YPMq7y5F8J3LkC5Hxg9PHyZ5K4cFv'
        target_h160 = decode_base58(target_address)
        target_script = p2pkh_script(target_h160)
        fee = 5000  # fee in satoshis
        # connect to programmingblockchain.com in testnet mode
        node = SimpleNode('programmingblockchain.com', testnet=True)
        # create a bloom filter of size 30 and 5 functions. Add a tweak.
        bf = BloomFilter(30, 5, 90210)
        # add the h160 to the bloom filter
        bf.add(h160)
        # load the bloom filter with the filterload command
        node.send(bf.filterload())
        # set start block to last_block from above
        start_block = bytes.fromhex(last_block_hex)
        # send a getheaders message with the starting block
        getheaders = GetHeadersMessage(start_block=start_block)
        node.send(getheaders)
        # wait for the headers message
        headers = node.wait_for(HeadersMessage)
        block_hashes = [b.hash() for b in headers.blocks]
        # initialize prev_tx, prev_index and prev_amount to None
        prev_tx, prev_index, prev_amount = None, None, None
        for h, tx_obj in node.get_filtered_block_txs(block_hashes):
            self.assertEqual(h, tx_obj.hash())
            tx_obj.testnet = True
            # loop through the tx outs
            for i, tx_out in enumerate(tx_obj.tx_outs):
                # if our output has the same address as our address we found it
                if tx_out.script_pubkey.address(testnet=True) == addr:
                    # we found our utxo. set prev_tx, prev_index, and tx
                    prev_tx = h
                    prev_index = i
                    prev_amount = tx_out.amount
                    self.assertEqual(h.hex(), 'b2cddd41d18d00910f88c31aa58c6816a190b8fc30fe7c665e1cd2ec60efdf3f')
                    self.assertEqual(i, 7)
                    break
            if prev_tx:
                break
        # create the TxIn
        tx_in = TxIn(prev_tx, prev_index)
        # calculate the output amount (previous amount minus the fee)
        output_amount = prev_amount - fee
        # create a new TxOut to the target script with the output amount
        tx_out = TxOut(output_amount, target_script)
        # create a new transaction with the one input and one output
        tx_obj = Tx(1, [tx_in], [tx_out], 0, testnet=True)
        # sign the only input of the transaction
        self.assertTrue(tx_obj.sign_input_p2pkh(0, private_key))
        # serialize and hex to see what it looks like
        want = '01000000013fdfef60ecd21c5e667cfe30fcb890a116688ca51ac3880f91008dd141ddcdb2070000006b483045022100ff77d2559261df5490ed00d231099c4b8ea867e6ccfe8e3e6d077313ed4f1428022033a1db8d69eb0dc376f89684d1ed1be75719888090388a16f1e8eedeb8067768012103dc585d46cfca73f3a75ba1ef0c5756a21c1924587480700c6eb64e3f75d22083ffffffff019334e500000000001976a914ad346f8eb57dee9a37981716e498120ae80e44f788ac00000000'
        self.assertEqual(tx_obj.serialize().hex(), want)
        # send this signed transaction on the network
        node.send_tx(tx_obj)
