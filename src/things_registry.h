#ifndef ThingsRegistry_H
#define ThingsRegistry_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdbool.h>
#include <openssl/x509v3.h>

#define CERTS_PATH "./certs/"

#define CA_CERTIFICATE "ca.cert.pem"
#define CA_PRIVATE_KEY "ca.private_key.pem"
#define DEVICE_PUBLIC_KEY "device.public_key.pem"
#define DEVICE_PRIVATE_KEY "device.private_key.pem"
#define DEVICE_CSR "device.csr"
#define DEVICE_CERTIFICATE "device.cert.pem"

#define SATR_INFO(message) printf("%s\n", message)

#define SATR_ERROR(message) printf("Error: %s\n", message)

bool hasCACertificateFile();

bool hasCAPrivateKeyFile();

bool hasDevicePublicKey();

bool hasDevicePrivateKey();

bool hasDeviceCsr();

bool hasDeviceCertificate();

char *getCACertifcatePath();

char *getCAPrivateKeyPath();

char *getDevicePublicKeyPath();

char *getDevicePrivateKeyPath();

char *getDeviceCsrPath();

char *getDeviceCertificatePath();

bool generateDeviceKeyPair();

bool generateDeviceCsr(char *);

bool generateDeviceCertificate(char *);

char *getThingName();

int x509AddExtension(X509 *, int, char *);

char *bin2hex(const unsigned char *, size_t);

typedef enum
{
    step_a, step_b, step_c, step_d
} base64_decodestep;

typedef struct
{
    base64_decodestep step;
    char plainchar;
} base64_decodestate;

size_t base64Decode(const char *, char *);

void base64_init_decodestate(base64_decodestate *);

int base64_decode_value(char);

int base64_decode_block(const char *, const int, char *, base64_decodestate *);

#ifdef __cplusplus
}
#endif

#endif