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

from quectel_at_lib import *

log = logging.getLogger('Modem_GPS_Service')


def checkSMS(modem):
    resp = modem.sendATcommand("+CSMS?")
    s = modem.splitResponse("+CSMS", resp[0])
    log.info("SMS service type: " + str(s[0]) + " MO:" + str(s[1]) + " MT:" + str(s[2]) + " BM:" + str(s[3]))
    resp = modem.sendATcommand("+CSCA?")
    s = modem.splitResponse("+CSCA", resp[0])
    log.info("SMS Service center:" + str(s[0]))


def init(modem):
    modem.resetCard()
    time.sleep(20.)
    modem.clearFPLMN()
    modem.allowRoaming()
    modem.logModemStatus()


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
    log.addHandler(logging.StreamHandler())
    log.setLevel(logging.DEBUG)
    QuectelModem.checkModemPresence(save_modem=True)
    try:
        modem = QuectelModem(0, True)
    except Exception as err:
        log.error(str(err))
        return

    log.info("SIM Status:" + modem.SIM_Status())
    if modem.checkSIM() == "NO SIM":
        log.error("No SIM card inserted")
        return

    option = "None"
    if len(sys.argv) > 1:
        option = sys.argv[1]
        log.info("Test Option:" + option)

    if modem.SIM_Status() == "SIM PIN":
        modem.setpin('0000')
        time.sleep(2.0)
        modem.checkSIM()

    modem.logModemStatus()

    if option == "init":
        init(modem)
    elif option == "cmd":
        if len(sys.argv) > 2:
            log.info("sending:" + sys.argv[2])
            resp = modem.sendATcommand(sys.argv[2], False)
            for r in resp:
                log.info(r)
        else:
            log.info("Missing command argument")
    elif option == "scan":
        if modem.SIM_Ready():
            rescan(modem)
    elif option == "oper":
        if len(sys.argv) > 2:
            log.info("selecting operator:" + sys.argv[2])
            if sys.argv[2].isdecimal():
                f = "numeric"
            else:
                f = 'long'
            modem.selectOperator(sys.argv[2], f, None)
        else:
            log.info("Missing operator name or ID")
    elif option == 'sms':
        checkSMS(modem)
    elif option == 'gps':
        checkGPS(modem)
    else:
        modem.allowRoaming()

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
            if not res and option == 'list':
                log.info(modem.visibleOperators())
                # try to Register from scratch
                # clear forbidden PLMN and allow roaming

    modem.close()


if __name__ == '__main__':
    main()
