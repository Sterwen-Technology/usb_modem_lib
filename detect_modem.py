# -------------------------------------------------------------------------------
# Name:        detect_modem
# Purpose:     Perform automatic modem detection
#
# Author:      Laurent Carré
#
# Created:     11/04/2024
# Copyright:   (c) Laurent Carré Sterwen Technology 2020-2024
# Licence:     Eclipse Public License 2.0
# -------------------------------------------------------------------------------


from modem_lib import QuectelModem, ModemException


def main():

    try:
        modem_def = QuectelModem.checkModemPresence(save_modem=True)
    except ModemException as err:
        print(f"No modem found or error in modem detection {err}")
        return
    print(f"Modem {modem_def['model']} found")


if __name__ == "__main__":
    main()
