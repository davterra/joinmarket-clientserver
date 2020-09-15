#!/usr/bin/env python3

from optparse import OptionParser

import sys
from twisted.python.log import startLogging
from twisted.web.server import Site
from twisted.internet import reactor
import txtorcon
from jmbase import get_log, set_logging_level, jmprint
from jmclient import jm_single, load_program_config, \
    WalletService, open_test_wallet_maybe, get_wallet_path, check_regtest, \
    add_base_options, PayjoinServer
from jmbase.support import EXIT_FAILURE, EXIT_ARGERROR
from jmbitcoin import amount_to_sat, amount_to_btc, encode_bip21_uri, \
     CCoinAddress

# txtorcon outputs erroneous warnings about hiddenservice directory strings,
# annoyingly, so we suppress it here:
import warnings
warnings.filterwarnings("ignore")

jlog = get_log()

bip78_amount = None
bip78_receiving_address = None

def setup_failed(arg):
    jlog.error("SETUP FAILED", arg)
    reactor.stop()

def create_onion_ep(t, hs_public_port):
    return t.create_onion_endpoint(hs_public_port)

def onion_listen(onion_ep, site):
    return onion_ep.listen(site)

def print_host(ep):
    """ Callback fired once the HS is available;
    receiver user needs a BIP21 URI to pass to
    the sender:
    """
    jmprint("Your hidden service is available. Please now pass "
            "this URI string to the sender to effect the payjoin "
            "payment:")
    jmprint(bip21_uri_from_onion_hostname(str(ep.getHost().onion_uri),
                                          ep.getHost().onion_port))
    jmprint("Keep this process running until the payment is received.")

def bip21_uri_from_onion_hostname(host, port):
    """ Encoding the BIP21 URI according to BIP78 specifications,
    and specifically only supporting a hidden service endpoint.
    Note: we hardcode http; no support for TLS over HS.
    Second, note we convert the global amount-in-sats bip78_amount
    to BTC denomination as expected by BIP21.
    """
    full_pj_string = "http://" + host + ":" + str(port)
    bip78_btc_amount = amount_to_btc(amount_to_sat(bip78_amount))
    # "safe" option is required to encode url in url unmolested:
    return encode_bip21_uri(bip78_receiving_address,
                            {"amount": bip78_btc_amount,
                             "pj": full_pj_string.encode("utf-8")},
                            safe=":/")

def start_tor(site, hs_public_port):
    d = txtorcon.connect(reactor)
    d.addCallback(create_onion_ep, hs_public_port)
    d.addErrback(setup_failed)
    d.addCallback(onion_listen, site)
    d.addCallback(print_host)

def receive_payjoin_main():
    global bip78_receiving_address
    global bip78_amount

    parser = OptionParser(usage='usage: %prog [options] [wallet file] [amount-to-receive]')
    add_base_options(parser)
    parser.add_option('-P', '--hs-port', action='store', type='int',
                      dest='hsport', default=7081,
                      help='port on which to serve the ephemeral hidden service.')
    parser.add_option('-g', '--gap-limit', action='store', type="int",
                      dest='gaplimit', default=6,
                      help='gap limit for wallet, default=6')
    parser.add_option('-m', '--mixdepth', action='store', type='int',
                      dest='mixdepth', default=0,
                      help="mixdepth to source coins from")
    parser.add_option('-a',
                      '--amtmixdepths',
                      action='store',
                      type='int',
                      dest='amtmixdepths',
                      help='number of mixdepths in wallet, default 5',
                      default=5)

    (options, args) = parser.parse_args()
    if len(args) < 2:
        parser.error('Needs a wallet, and a receiving amount in bitcoins or satoshis')
        sys.exit(EXIT_ARGERROR)
    wallet_name = args[0]
    try:
        # amount is stored internally in sats, but will be decimal in URL.
        bip78_amount = amount_to_sat(args[1])
    except:
        parser.error("Invalid receiving amount passed: " + bip78_amount)
        sys.exit(EXIT_FAILURE)
    if bip78_amount < 0:
        parser.error("Receiving amount must be a positive number")
        sys.exit(EXIT_FAILURE)
    load_program_config(config_path=options.datadir)

    check_regtest()

    wallet_path = get_wallet_path(wallet_name, None)
    max_mix_depth = max([options.mixdepth, options.amtmixdepths - 1])
    wallet = open_test_wallet_maybe(
        wallet_path, wallet_name, max_mix_depth,
        wallet_password_stdin=options.wallet_password_stdin,
        gap_limit=options.gaplimit)
    wallet_service = WalletService(wallet)

    while not wallet_service.synced:
        wallet_service.sync_wallet(fast=not options.recoversync)
    wallet_service.startService()
    # having enforced wallet sync, we can check if we have coins
    # to do payjoin in the mixdepth
    if wallet_service.get_balance_by_mixdepth()[options.mixdepth] == 0:
        jlog.error("Cannot do payjoin from mixdepth " + str(
            options.mixdepth) + ", no coins. Shutting down.")
        sys.exit(EXIT_ARGERROR)

    # the receiving address is sourced from the 'next' mixdepth
    # to avoid clustering of input and output:
    next_mixdepth = (options.mixdepth + 1) % (
        wallet_service.wallet.mixdepth + 1)
    bip78_receiving_address = wallet_service.get_internal_addr(next_mixdepth)

    pj_server = PayjoinServer(wallet_service, options.mixdepth,
                    CCoinAddress(bip78_receiving_address), bip78_amount)
    site = Site(pj_server)
    site.displayTracebacks = False
    jmprint("Attempting to start onion service on port: " + str(
        options.hsport) + " ...")
    start_tor(site, options.hsport)
    reactor.run()

if __name__ == "__main__":
    receive_payjoin_main()
    jmprint('done')
