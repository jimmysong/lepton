from io import BytesIO
from logging import getLogger
from os import unlink
from os.path import exists
from unittest import TestCase

from block import (
    GENESIS_BLOCK_HEADER,
    TESTNET_GENESIS_BLOCK_HEADER,
    LOWEST_BITS,
    Block,
)
from helper import (
    calculate_new_bits,
    encode_varint,
    hash256,
    read_varint,
)
from network import (
    CFCheckPointMessage,
    CFHeadersMessage,
    GetCFCheckPointMessage,
    GetCFHeadersMessage,
    GetHeadersMessage,
    HeadersMessage,
    SimpleNode,
)
from tx import Tx


LOGGER = getLogger(__name__)


class BlockStore:

    def __init__(self, node, filename=None, full=False, include=None):
        self.node = node
        self.testnet = node.testnet
        if filename is None:
            if self.testnet:
                self.filename = 'testnet.blocks'
            else:
                self.filename = 'mainnet.blocks'
        else:
            self.filename = filename
        self.full = full
        self.include = include
        self.start_height = 0
        if not exists(self.filename):
            # new store
            # start from the genesis block
            if self.testnet:
                header = TESTNET_GENESIS_BLOCK_HEADER
            else:
                header = GENESIS_BLOCK_HEADER
            self.headers = [Block.parse_header(BytesIO(header))]
        else:
            with open(self.filename, 'rb') as f:
                headers = []
                file_height = read_varint(f)
                if self.full:
                    self.start_height = 0
                elif self.include and self.include < file_height:
                    # start of difficulty adjustment that includes this block
                    self.start_height = (self.include // 2016) * 2016
                else:
                    # one full difficulty adjustment + remaining
                    self.start_height = (file_height // 2016 - 1) * 2016
                for height in range(self.start_height, file_height + 1):
                    header = Block.parse_header(f)
                    header.cfheader = f.read(32)
                    header.cfhash = f.read(32)
                    header.height = height
                    headers.append(header)
                self.headers = headers[::-1]
        self.headers_lookup = {h.hash(): h for h in self.headers}

    def store_height(self):
        '''return the height of the last block we have'''
        return self.start_height + len(self.headers) - 1

    def header_by_height(self, height):
        index = height - self.start_height
        if index >= len(self.headers) or index < 0:
            raise RuntimeError('Block {} not in store'.format(height))
        return self.headers[index]

    def header_by_hash(self, h):
        header = self.headers_lookup.get(h)
        if header is None:
            raise RuntimeError('Block {} not in store'.format(h))
        return header
        
    def save(self):
        store_height = self.store_height()
        if exists(self.filename):
            with open(self.filename, 'rb') as f:
                file_height = read_varint(f)
                if store_height == file_height:
                    # no need to save as we're synced
                    return
                rest = f.read()
        else:
            file_height = -1
            rest = b''
        with open(self.filename, 'wb') as f:
            f.write(encode_varint(store_height))
            for height in range(store_height, file_height, -1):
                h = self.header_by_height(height)
                f.write(h.serialize())
                f.write(h.cfheader)
                f.write(h.cfhash)
            f.write(rest)

    def update(self, stop_height=None):
        if stop_height is None:
            stop_height = self.node.latest_block
        start_height = self.store_height()
        previous = self.headers[-1]
        # find the first epoch timestamp
        epoch_first_block = self.headers[(len(self.headers) // 2016) * 2016]
        epoch_first_timestamp = epoch_first_block.timestamp
        epoch_bits = epoch_first_block.bits
        # download blocks we don't have
        current_height = start_height + 1
        while current_height <= stop_height:
            LOGGER.info('downloading headers {} to {}'.format(current_height, current_height+1999))
            # ask for headers
            getheaders = GetHeadersMessage(start_block=previous.hash())
            self.node.send(getheaders)
            headers = self.node.wait_for(HeadersMessage)
            # validate headers
            for header in headers.blocks:
                if not header.check_pow():
                    raise RuntimeError('{}: PoW is invalid'.format(current_height))
                if header.prev_block != previous.hash():
                    raise RuntimeError('{}: not sequential'.format(current_height))
                if current_height % 2016 == 0:
                    # difficulty adjustment
                    time_diff = previous.timestamp - epoch_first_timestamp
                    epoch_bits = calculate_new_bits(previous.bits, time_diff)
                    expected_bits = epoch_bits
                    epoch_first_timestamp = header.timestamp
                elif self.testnet and header.timestamp > previous.timestamp + 20 * 60:
                    expected_bits = LOWEST_BITS
                else:
                    expected_bits = epoch_bits
                if header.bits != expected_bits:
                    raise RuntimeError('{}: bad bits {} vs {}'.format(
                        current_height, header.bits.hex(), expected_bits.hex()))
                previous = header
                current_height += 1
                self.headers.append(header)
                self.headers_lookup[header.hash()] = header
                if current_height > stop_height:
                    break
        LOGGER.info('downloaded headers to {} inclusive'.format(stop_height))
        # download compact filter checkpoints
        getcfcheckpoint = GetCFCheckPointMessage(stop_hash=self.headers[-1].hash())
        self.node.send(getcfcheckpoint)
        cfcheckpoint = self.node.wait_for(CFCheckPointMessage)
        # download all cfheaders
        prev_filter_header = b'\x00' * 32
        cfcheckpoint.filter_headers.append(None)
        for i, cpfilter_header in enumerate(cfcheckpoint.filter_headers):
            if i == 0:
                start = 0
            else:
                start = i * 1000 + 1
            end = (i+1) * 1000
            if end <= start_height:
                prev_filter_header = cpfilter_header
                continue
            if end > stop_height:
                end = stop_height
                stop_hash = self.headers[-1].hash()
            else:
                stop_hash = self.header_by_height(end).hash()
            LOGGER.info('getting filters range {} to {}'.format(start, end))
            getcfheaders = GetCFHeadersMessage(
                start_height=start, stop_hash=stop_hash)
            self.node.send(getcfheaders)
            cfheaders = self.node.wait_for(CFHeadersMessage)
            if prev_filter_header != cfheaders.previous_filter_header:
                raise RuntimeError('Non-sequential CF headers')
            # validate all cfheaders
            for j, filter_hash in enumerate(cfheaders.filter_hashes):
                header = self.header_by_height(start + j)
                filter_header = hash256(filter_hash[::-1] + prev_filter_header[::-1])[::-1]
                prev_filter_header = filter_header
                header.cfhash = filter_hash
                header.cfheader = filter_header
                header.height = start + j
            if cpfilter_header is not None and cpfilter_header != prev_filter_header:
                raise RuntimeError('CF header not what we expected')


class BlockStoreTest(TestCase):

    def test_load(self):
        filename = 'mainnet.blocks.tmp'
        if exists(filename):
            unlink(filename)
        height = 4032
        node = SimpleNode(host='btcd0.lightning.computer')
        cs = BlockStore(node=node, filename=filename, full=True)
        cs.update(height)
        self.assertEqual(cs.store_height(), height)
        cs.save()
        new_cs = BlockStore(node=node, filename=filename, full=True)
        self.assertEqual(new_cs.store_height(), height)
        height = 6048
        new_cs.update(height)
        new_cs.save()
        new_cs.save()
        self.assertEqual(new_cs.store_height(), height)
        new_cs = BlockStore(node=node, filename=filename)
        self.assertEqual(new_cs.store_height(), height)
        self.assertEqual(len(new_cs.headers), 2017)
        height = 6148
        new_cs.update(height)
        self.assertEqual(new_cs.store_height(), height)
        new_cs.save()
        unlink(filename)
        filename = 'testnet.blocks.tmp'
        if exists(filename):
            unlink(filename)
        height = 4032
        node = SimpleNode(host='programmingblockchain.com', testnet=True)
        cs = BlockStore(node=node, filename=filename, full=True)
        cs.update(height)
        self.assertEqual(len(cs.headers), height + 1)
        cs.save()
        unlink(filename)
