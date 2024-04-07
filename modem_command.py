# -------------------------------------------------------------------------------
# Name:        Test Modem
# Purpose:     Perform basic testing of the modem function
#
# Author:      Laurent Carré
#
# Created:     11/02/2020
# Copyright:   (c) Laurent Carré Sterwen Technologies 2020-2024
# Licence:     Eclipse Public License 2.0
# -------------------------------------------------------------------------------

import sys
import time
from argparse import ArgumentParser

from usb_modem_at_lib import *

log = logging.getLogger('Modem_GPS_Service')


def _parser():
    p = ArgumentParser(description=sys.argv[0])
    p.add_argument('-R', '--reset', action='store_true')
    p.add_argument('-gps', '--gps', action='store_true')
    p.add_argument('-gps_off', '--gps_off', action='store_true')
    p.add_argument('-v', '--verbose', action='store_true')
    p.add_argument('-d', '--detect', action='store_true')
    p.add_argument('-c', '--cmd', action='store', default=None)
    p.add_argument('-w', '--wait', action='store', type=float, default=0.0)
    p.add_argument('-p', '--pin', action='store')
    return p


def checkSMS(modem):
    resp = modem.sendATcommand("+CSMS?")
    s = modem.splitResponse("+CSMS", resp[0])
    log.info("SMS service type: " + str(s[0]) + " MO:" + str(s[1]) + " MT:" + str(s[2]) + " BM:" + str(s[3]))
    resp = modem.sendATcommand("+CSCA?")
    s = modem.splitResponse("+CSCA", resp[0])
    log.info("SMS Service center:" + str(s[0]))


def init_modem(modem):
    modem.clearFPLMN()
    modem.allowRoaming()


def rescan(modem):
    log.info("Resetting network scan mode")
    modem.sendATcommand('+QCFG=”nwscanmode”,0,1')
    modem.selectOperator('AUTO')


def checkGPS(modem):
    if modem.gpsStatus():
        log.info("Reading GPS")
        sg = modem.getGpsStatus()
        if sg['fix']:
            pf = "LAT {0} LONG {1}".format(sg['Latitude'], sg['Longitude'])
            log.info(pf)
        else:
            log.info("GPS not fixed")
    else:
        log.info("GPS is turned off => turning on")
        modem.gpsOn()


def main():
    parser = _parser()
    opts = parser.parse_args()

    log.addHandler(logging.StreamHandler())
    if opts.verbose:
        log.setLevel(logging.DEBUG)
    else:
        log.setLevel(logging.INFO)
    if opts.detect:
        print("Detection of the modem...")
        try:
            modem_def = QuectelModem.checkModemPresence(save_modem=True, verbose=opts.verbose)
        except ModemException as err:
            print(f"Error during modem detection {err}")
            return 2
        print(f"Modem type {modem_def['model']} found with control tty {modem_def['tty_list'][2].tty_name}")

    try:
        modem = QuectelModem(0, True)
    except Exception as err:
        log.error(str(err))
        return 2

    if opts.reset:
        print("Performing soft reset on modem")
        modem.resetCard()
        print("Soft reset done - the modem is not ready")
        if opts.wait > 0:
            print(f"Waiting {opts.wait} seconds")
            time.sleep(opts.wait)
        else:
            return

    if opts.gps:
        checkGPS(modem)

    if not modem.checkSIM(opts.pin):
        log.error("No SIM card inserted or incorrect PIN code")
        return 1
    print("Modem and SIM card ready")


    if modem.SIM_Ready():
        # we have a SIM so look how it goes

        res = modem.networkStatus()

        if not res:
            # let's see what is the situation
            state = modem.regStatus()
            log.info("Modem registration status:" + state)
            if state == "IN PROGRESS":
                # just wait
                log.info("Registration in progress => waiting")
                nb_attempt = 0
                while nb_attempt < 10:
                    time.sleep(2.0)
                    res = modem.networkStatus()
                    if res: break
                    nb_attempt += 1
            if not res:
                log.info(modem.visibleOperators())
                # try to Register from scratch
                # clear forbidden PLMN and allow roaming

    modem.close()


if __name__ == '__main__':
    exit_val = main()
    if exit_val is None:
        exit_val = 0
    exit(exit_val)
