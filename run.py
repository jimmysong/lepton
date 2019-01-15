from wallet import Wallet

from cmd import Cmd


class MyPrompt(Cmd):

    def __init__(self):
        super().__init__()
        self.w = None

    def do_exit(self, inp):
        '''Exit Program'''
        print('Program Locked')
        return True

    def do_load(self, inp):
        '''Load Wallet'''
        if inp:
            print('Loading Wallet: {}'.format(inp))
            self.w = Wallet.open(inp)
        else:
            print('Loading Wallet')
            self.w = Wallet.open()

    def do_update(self, inp):
        '''Sync Wallet to the latest'''
        if self.w is None:
            print('Please load the wallet first')
        else:
            print('Updating')
            self.w.update()

    def do_utxos(self, inp):
        '''List utxos'''
        if self.w is None:
            print('Please load the wallet first')
        else:
            print('UTXOS')
            for utxo in self.w.get_utxos():
                print(utxo)

    def do_balance(self, inp):
        '''Get balance of the wallet'''
        if self.w is None:
            print('Please load the wallet first')
        else:
            print('{} tBTC'.format(self.w.balance() / 100000000))

    def do_received(self, inp):
        '''Get total received by the wallet'''
        if self.w is None:
            print('Please load the wallet first')
        else:
            print('{} tBTC'.format(self.w.total_received() / 100000000))

    def do_spent(self, inp):
        '''Get amount spent by the wallet'''
        if self.w is None:
            print('Please load the wallet first')
        else:
            print('{} tBTC'.format(self.w.spent() / 100000000))

    def do_used_addresses(self, inp):
        '''Get addresses that have been used'''
        if self.w is None:
            print('Please load the wallet first')
        else:
            external, internal = self.w.addresses()
            print('External:')
            for addr in external:
                print(addr)
            print('\nInternal:')
            for addr in external:
                print(addr)

    def do_new_address(self, inp):
        '''Get a new address to receive coins'''
        if self.w is None:
            print('Please load the wallet first')
        else:
            print(self.w.address())

    def do_send(self, inp):
        '''Send some amount to another address'''
        args = inp.split()
        if len(args) == 0:
            addr = input('To what address? ')
            amount = int(float(input('How much in BTC? '))*100000000)
        else:
            addr = args[1]
            amount = int(float(args[0])*100000000)
        print(self.w.simple_send(addr, amount))



MyPrompt().cmdloop()
