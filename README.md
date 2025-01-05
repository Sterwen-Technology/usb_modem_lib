# Modem USB Lib
Python package and CLI to manage Quectel (and others) USB modems
Lightweight and simple API to control the modem. Python only and limited dependencies.

The package is a simpler alternative to the ubiquitous ModemManager for developers that require a simple a full control of the modem behavior.
Only the AT commands interface is supported, not the QMI one. For those who wants QMI, back to ModemManager.

## Features

- modem status: SIM presence, IMEI,...
- SIM card: IMSI, ICC-ID, operator list
- Network attachment: operator, RAT, band, RSSI, LAC, CI
- Attachment management: operator and RAT change
- Available networks
- Modem soft reset and return to factory default
- GPS: turning on and off, getting GPS data
- SMS send and receive

## CLI
`modem_command

options:

  -h, --help            show this help message and exit

  -R, --reset           Perform a soft reset of the modem

  -gps, --gps           Display/send GPS status - turn it on

  -gps_off, --gps_off   Turn the GPS off

  -v, --verbose         Verbose mode

  -d, --detect          Detect the modem, shall be run once

  -c CMD, --cmd CMD     Send a AT command to the modem

  -w WAIT, --wait WAIT  Wait time in sec when needed

  -p PIN, --pin PIN     PIN code to unlock the SIM card

  -l, --list            List all visible operators and technology

  -to SMS_TO, --sms_to SMS_TO Number(MSISDN) address for SMS

  -t TEXT, --text TEXT  Text of the SMS

  -sms, --sms           SMS feature parameters

  -i, --init            Send default configuration to modem

  -del, --delete_sms    Delete SMS after reading

  -r {all,unread}, --read_sms {all,unread}
                        Read SMS

  -log_at, --log_at     Log all low level exchanges with the modem

  -rescan, --rescan     Start scanning for operator

  -dir DIR, --dir DIR   Directory for modem configuration file
 `

## Modem detection and information store

By using the --detect option the software detects the presence, USB ports usable and modem type. That information is stored in a json file *modemN.json* when [N] is the modem number (starting at 0).
The directory where the file is located is determined by the following options by order of priority:

1 - Using the -dir option from the command line
2 - Using the MODEM_DIR environment variable
3 - Using the HOME directory, or SUDO_USER home directory

The --detect option shall be run before any other use of the library. It shall be run via sudo.

## API

The API is based on single class **QuectelModem** that needs to be instantiated for each modem managed by it.

[generated documentation](usb_modem_at_lib.html)

## Support

For any problem encountered, please open an issue in this repository.

## Roadmap
The current stable version is V0.93. Documentation is aligned on this version.


## Contributing

All contributions welcome. 

## Authors and acknowledgment
Laurent Carré - [Sterwen Technology](http://www.sterwen-technology.eu). 

## License
Eclipse Public License 2.0. for all development from Sterwen Technology
GNU Lesser GPL v3.0 for Python-can
Apache License 2.0 for grpc

## Project status
Under development.

