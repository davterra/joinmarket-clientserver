
"""
Test doing payjoin joins (with message channel layer mocked)
"""

import os
import sys
import pytest
from twisted.internet import reactor
from twisted.web.server import Site
from jmbase import get_log
from jmbitcoin import (CCoinAddress, encode_bip21_uri,
                       amount_to_btc, amount_to_sat)
from jmclient import cryptoengine
from jmclient import (load_test_config, jm_single,
                      SegwitLegacyWallet, SegwitWallet,
                      PayjoinServer, parse_payjoin_setup, send_payjoin)
from commontest import make_wallets
from test_coinjoin import make_wallets_to_list, create_orderbook, sync_wallets

testdir = os.path.dirname(os.path.realpath(__file__))
log = get_log()

def getbals(wallet_service, mixdepth):
    """ Retrieves balances for a mixdepth and the 'next'
    """
    bbm = wallet_service.get_balance_by_mixdepth()
    return (bbm[mixdepth], bbm[(mixdepth + 1) % (wallet_service.mixdepth + 1)])

def final_checks(wallet_services, amount, txfee, ssb, rsb, source_mixdepth=0):
    """We use this to check that the wallet contents are
    as we've expected according to the test case.
    amount is the payment amount going from spender to receiver.
    txfee is the bitcoin network transaction fee, paid by the spender.
    ssb, rsb are spender and receiver starting balances, each a tuple
    of two entries, source and destination mixdepth respectively.
    """
    jm_single().bc_interface.tickchain()
    sync_wallets(wallet_services)
    spenderbals = getbals(wallet_services[1], source_mixdepth)
    receiverbals = getbals(wallet_services[0], source_mixdepth)
    # is the payment received?
    receiver_newcoin_amt = receiverbals[1] - rsb[1]
    if not receiver_newcoin_amt >= amount:
        print("Receiver expected to receive at least: ", amount,
              " but got: ", receiver_newcoin_amt)
        return False
    # assert that the receiver received net exactly the right amount
    receiver_spentcoin_amt = rsb[0] - receiverbals[0]
    if not receiver_spentcoin_amt >= 0:
        # for now allow the non-cj fallback case
        print("receiver's spent coin should have been positive, was: ", receiver_spentcoin_amt)
        return False
    if not receiver_newcoin_amt == amount + receiver_spentcoin_amt:
        print("receiver's new coins should have been: ", amount + receiver_spentcoin_amt,
              " but was: ", receiver_newcoin_amt)
        return False

    # Spender-side check
    # assert that the spender's total ending minus total starting
    # balance is the amount plus the txfee given.
    if not (sum(spenderbals) - sum(ssb) + txfee + amount) == 0:
        print("Taker should have spent: ", txfee + amount,
              " but spent: ", sum(ssb) - sum(spenderbals))
        return False
    return True

@pytest.mark.parametrize('wallet_cls, wallet_structures, mean_amt',
        [ # note we have removed LegacyWallet test cases.
         ([SegwitLegacyWallet, SegwitLegacyWallet],
          [[1, 3, 0, 0, 0]] * 2, 2.0),
         #([SegwitWallet, SegwitWallet],
         # [[1, 0, 0, 0, 0]] * 2, 4.0),
         #([SegwitLegacyWallet, SegwitWallet],
         # [[1, 3, 0, 0, 0]] * 2, 2.0),
         #([SegwitWallet, SegwitLegacyWallet],
         # [[1, 0, 0, 0, 0]] * 2, 4.0),
         ])
def test_simple_payjoin(monkeypatch, tmpdir, setup_cj, wallet_cls,
                        wallet_structures, mean_amt):
    def raise_exit(i):
        raise Exception("sys.exit called")
    monkeypatch.setattr(sys, 'exit', raise_exit)
    wallet_services = []
    wallet_services.append(make_wallets_to_list(make_wallets(
        1, wallet_structures=[wallet_structures[0]],
        mean_amt=mean_amt, wallet_cls=wallet_cls[0]))[0])
    wallet_services.append(make_wallets_to_list(make_wallets(
            1, wallet_structures=[wallet_structures[1]],
            mean_amt=mean_amt, wallet_cls=wallet_cls[1]))[0])
    jm_single().bc_interface.tickchain()
    sync_wallets(wallet_services)

    # For accounting purposes, record the balances
    # at the start.
    rsb = getbals(wallet_services[0], 0)
    ssb = getbals(wallet_services[1], 0)

    cj_amount = int(1.1 * 10**8)
    # destination address is in 2nd mixdepth of receiver
    # (note: not first because sourcing from first)
    bip78_receiving_address = wallet_services[0].get_internal_addr(1)
    pjs = PayjoinServer(wallet_services[0], 0,
                  CCoinAddress(bip78_receiving_address), cj_amount)
    site = Site(pjs)

    # NB The connectivity aspects of the BIP78 tests are in
    # test/payjoin[client/server].py as they are time heavy
    # and require extra setup. This server is TCP only.
    reactor.listenTCP(47083, site)
    # setup of spender
    bip78_btc_amount = amount_to_btc(amount_to_sat(cj_amount))
    bip78_uri = encode_bip21_uri(bip78_receiving_address,
                            {"amount": bip78_btc_amount,
                             "pj": b"http://127.0.0.1:47083"},
                            safe=":/")
    manager = parse_payjoin_setup(bip78_uri, wallet_services[1], 0)
    reactor.callWhenRunning(send_payjoin, manager)
    reactor.run()
    # Although the above OK is proof that a transaction went through,
    # it doesn't prove it was a good transaction! Here do balance checks:
    assert final_checks(wallet_services, cj_amount,
                        manager.final_psbt.get_fee(), ssb, rsb)

@pytest.fixture(scope='module')
def setup_cj():
    load_test_config()
    jm_single().config.set('POLICY', 'tx_broadcast', 'self')
    jm_single().bc_interface.tick_forward_chain_interval = 5
    jm_single().bc_interface.simulate_blocks()
    #see note in cryptoengine.py:
    cryptoengine.BTC_P2WPKH.VBYTE = 100
    yield None
    # teardown
    for dc in reactor.getDelayedCalls():
        dc.cancel()
