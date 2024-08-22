# SMLIGHT CC Flasher
Firmware flasher for Texas Instruments CC13xx / CC26xx Zigbee SoCs.


## Installation
```console
$ pip install smlight-cc-flasher
```
## Usage
While this flasher was based on `cc2538-bsl`, some CLI options have changed:
-  `-p, --port` is now `-d, --device` for input `/dev/ttyUSB0` or `socket://host:port`
-  New `--host` to specify network host, as alternative to `-d socket://host:port`, however if specified with USB `-d /dev/ttyUSB0`, will attempt network BSL only.
-  `-p, --port` now specifies network port (default 6638)
- New `--m33` option, required for CC2654P10 chips (i.e SLZB-0xP10)
- New `-bootloader-reset <mode>` to specify BSL mode
- `--read` now outputs to dedicated file specified with `--output <file>`
- Some other options removed.

See `smlight-cc-flasher --help` for more details.

### Flashing Firmware Examples
USB (on Linux/Mac will attempt to autodetect device if not specified):
```bash
$ smlight-cc-flasher -ewv \
    [-d /dev/ttyUSB0] znp_LP_CC1352P7.hex
```

SLZB-06x over network:
```bash
$ smlight-cc-flasher -ewv \
    --host slzb-06.local [--port 6638] \
    znp_LP_CC1352P7.hex
```
or
```bash
$ smlight-cc-flasher -ewv \
    --device socket://10.42.0.2:6638 \
    znp_LP_CC1352P7.hex
```

SLZB-06P10 USB flash with network bootloader (currently SLZB authentication is not supported):
```bash
$ smlight-cc-flasher -ewv \
    --device /dev/ttyUSB0 --host slzb-06.local --m33 \
    znp_LP_CC1352P7.hex
```


### Other notes
Bootloader settings from the new firmware are displayed before flashing. If the new firmware disables bootloader you are required to provide the `--force` flag to proceed with flashing.

For all the CC13xx and CC26xx families, the ROM bootloader is configured through the `BL_CONFIG` 'register' in CCFG. `BOOTLOADER_ENABLE` should be set to `0xC5` to enable the bootloader in the first place.

This is enough if the chip has not been programmed with a valid image. If a valid image is present, then the remaining fields of `BL_CONFIG` and the `ERASE_CONF` register must also be configured correctly:

* Select a DIO by setting `BL_PIN_NUMBER`
* Select an active level (low/high) for the DIO by setting `BL_LEVEL`
* Enable 'failure analysis' by setting `BL_ENABLE` to `0xC5`
* Make sure the `BANK_ERASE` command is enabled: The `BANK_ERASE_DIS_N` bit in the `ERASE_CONF` register in CCFG must be set. `BANK_ERASE` is enabled by default.

##### Authors
Tim Lunn (c) 2024, <tl@smlight.tech>

Based on [cc2358-bsl] by:

Jelmer Tiete (c) 2014, <jelmer@tiete.be>

Loosely based on [stm32loader] by Ivan A-R <ivan@tuxotronic.org>

[cc2358-bsl]: https://github.com/JelmerT/cc2538-bsl "cc3258-bsl"
[stm32loader]: https://github.com/jsnyder/stm32loader "stm32loader"