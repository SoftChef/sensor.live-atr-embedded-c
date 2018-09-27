# sensor.live-atr-embedded-c

## Overview

This document will help your device connect to AWS IoT quickly. Mainly to speed up the process of certificate exchanging complied to AWS IoT authentication.

## Prepare

Environment

- Git clone this repository into your project folder and layout
- Create "certs" directory in your project folder

Packages

- AWS IoT SDK for embedded C https://github.com/aws/aws-iot-device-sdk-embedded-C
- OpenSSL https://github.com/openssl/openssl

sensor.live

- Enable SATR on sensor.live, you will get root_ca.cert.pem, ca.cert.pem and ca.private_key.pem.
- Put the pem files into ./certs directory.

## API Documentation

#### generateDeviceCertificate(char *thing_name)

Generate device certificate.

You can customize the thing name, please ensure the thing name is given uniquely.

The naming rule is based on AWS IoT requirement: Must contain only alphanumeric characters and/or the following: -_:

If your thing_name is null, alternatively, the thing name will generate from the device certificate.

#### hasDeviceCertificate()

Check device certificate exists.

#### getThingName()

Get the thing name. Your customized name or from the device certificate.

## License

This SDK is distributed under the GNU GENERAL PUBLIC LICENSE Version 3, see LICENSE for more information.

## Support

If you have technical questions about sensor.live-atr, contact sensor.live support poke@sensor.live.

