#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <stdint.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/x509v3.h>
#include "things_registry.h"

bool hasCertFile(char *file_name) {
    bool result;
    char file_path[50];
    strcpy(file_path, CERTS_PATH);
    strcat(file_path, file_name);
    FILE* fp = fopen(file_path, "r");
    if (fp) {
        result = true;
        fclose(fp);
    } else {
        result = false;
    }
    return result;
}

int getFileSize(FILE *fp) {
    int prev = ftell(fp);
    fseek(fp, 0L, SEEK_END);
    int size = ftell(fp);
    fseek(fp, prev, SEEK_SET);
    return size;
}

bool hasCACertificateFile() {
    return hasCertFile(CA_CERTIFICATE);
}

bool hasCAPrivateKeyFile() {
    return hasCertFile(CA_PRIVATE_KEY);
}

bool hasDeviceCertificate() {
    return hasCertFile(DEVICE_CERTIFICATE);
}

bool hasDeviceCsr() {
    return hasCertFile(DEVICE_CSR);
}

bool hasDevicePublicKey() {
    return hasCertFile(DEVICE_PUBLIC_KEY);
}

bool hasDevicePrivateKey() {
    return hasCertFile(DEVICE_PRIVATE_KEY);
}

char *getFilePath(char *file_name) {
    static char file_path[50];
    strcpy(file_path, CERTS_PATH);
    strcat(file_path, file_name);
    return file_path;
}

char *getCACertifcatePath() {
    return getFilePath(CA_CERTIFICATE);
}

char *getCAPrivateKeyPath() {
    return getFilePath(CA_PRIVATE_KEY);
}

char *getDevicePublicKeyPath() {
    return getFilePath(DEVICE_PUBLIC_KEY);
}

char *getDevicePrivateKeyPath() {
    return getFilePath(DEVICE_PRIVATE_KEY);
}

char *getDeviceCsrPath() {
    return getFilePath(DEVICE_CSR);
}

char *getDeviceCertificatePath() {
    return getFilePath(DEVICE_CERTIFICATE);
}

bool _generateDeviceKeyPair() {
    BIGNUM *bn = BN_new();
    if (BN_set_word(bn, RSA_F4) != 1) {
        SATR_ERROR("Set BN word failed.");
        return false;
    }
    RSA *rsa = RSA_new();
    if (RSA_generate_key_ex(rsa, 2048, bn, NULL) != 1) {
        SATR_ERROR("Generate RSA key failed.");
        return false;
    }
    BIO *device_public_key = BIO_new_file(getDevicePublicKeyPath(), "w+");
    if (PEM_write_bio_RSAPublicKey(device_public_key, rsa) != 1) {
        SATR_ERROR("Save RSA public key failed.");
        return false;
    }
    BIO *device_private_key = BIO_new_file(getDevicePrivateKeyPath(), "w+");
    if (PEM_write_bio_RSAPrivateKey(device_private_key, rsa, NULL, NULL, 0, NULL, NULL) != 1) {
        SATR_ERROR("Save RSA private key failed.");
        return false;
    }
    RSA_free(rsa);
    BN_free(bn);
    BIO_free_all(device_public_key);
    BIO_free_all(device_private_key);
    return true;
}

bool _generateDeviceCsr(char *thing_name) {
    X509_REQ *x509_request = X509_REQ_new();
    if (X509_REQ_set_version(x509_request, 1) != 1) {
        SATR_ERROR("Set x509 request version 1 failed.");
        return false;
    }
    X509_NAME *x509_name = X509_REQ_get_subject_name(x509_request);
    if (X509_NAME_add_entry_by_txt(x509_name, "CN", MBSTRING_ASC, (const unsigned char*)thing_name, -1, -1, 0) != 1) {
        SATR_ERROR("Set common name failed.");
        return false;
    }
    BIO *device_private_key = BIO_new(BIO_s_file());
    BIO_read_filename(device_private_key, getDevicePrivateKeyPath());
    EVP_PKEY *device_private_key_pem = PEM_read_bio_PrivateKey(device_private_key, NULL, 0, NULL);
    if (!device_private_key_pem) {
        SATR_ERROR("Can't read device private key file.");
        return false;
    }
    if (X509_REQ_set_pubkey(x509_request, device_private_key_pem) != 1) {
        SATR_ERROR("Set device request public key failed.");
        return false;
    }
    if (X509_REQ_sign(x509_request, device_private_key_pem, EVP_sha256()) <= 0) {
        SATR_ERROR("Sign device request failed.");
        return false;
    }
    BIO *device_csr = BIO_new_file(getDeviceCsrPath(), "w");
    if (PEM_write_bio_X509_REQ(device_csr, x509_request) != 1) {
        SATR_ERROR("Save device request file failed.");
    }
    X509_REQ_free(x509_request);    
    EVP_PKEY_free(device_private_key_pem);
    BIO_free_all(device_csr);    
    return true;
}

bool _generateDeviceCertificate() {
    BIO *device_csr = BIO_new(BIO_s_file());
    BIO_read_filename(device_csr, getDeviceCsrPath());
    X509_REQ *device_csr_pem = PEM_read_bio_X509_REQ(device_csr, NULL, 0, NULL);
    if (!device_csr_pem) {
        SATR_ERROR("Can't read device csr file.");
        return false;
    }
    BIO *ca_certificate = BIO_new(BIO_s_file());
    BIO_read_filename(ca_certificate, getCACertifcatePath());
    X509 *ca_certificate_pem = PEM_read_bio_X509(ca_certificate, NULL, 0, NULL);
    if (!ca_certificate_pem) {
        SATR_ERROR("Can't read ca certificate file.");
        return false;
    }
    BIO *ca_private_key = BIO_new(BIO_s_file());
    BIO_read_filename(ca_private_key, getCAPrivateKeyPath());
    EVP_PKEY *ca_private_key_pem = PEM_read_bio_PrivateKey(ca_private_key, NULL, 0, NULL);
    if (!ca_private_key_pem) {
        SATR_ERROR("Can't read ca certificate file.");
        return false;
    }
    X509 *new_certificate = X509_new();
    if (X509_set_version(new_certificate, 2) != 1) {
        SATR_ERROR("Set device certificate version 2 failed.");
        return false;
    }
    if (X509_set_subject_name(new_certificate, X509_REQ_get_subject_name(device_csr_pem)) != 1) {
        SATR_ERROR("Set device certificate subject failed.");
        return false;
    }
    if (X509_set_issuer_name(new_certificate, X509_get_subject_name(ca_certificate_pem)) != 1) {
        SATR_ERROR("Set device certificate issuer name failed.");
        return false;
    }
    if (X509_set_pubkey(new_certificate, X509_REQ_get_pubkey(device_csr_pem)) != 1) {
        SATR_ERROR("Set device certificate public key from csr failed.");
        return false;
    }
    if (!X509_gmtime_adj(X509_get_notBefore(new_certificate), 0)) {
        SATR_ERROR("Set device certificate start time failed.");
        return false;
    }
    if (!X509_gmtime_adj(X509_get_notAfter(new_certificate), 31536000)) {
        SATR_ERROR("Set device certificate end time failed.");
        return false;
    }
    x509AddExtension(new_certificate, NID_basic_constraints, "CA:FALSE");
    x509AddExtension(new_certificate, NID_subject_key_identifier, "hash");
    x509AddExtension(new_certificate, NID_authority_key_identifier, "keyid,issuer");
    if (!X509_sign(new_certificate, ca_private_key_pem, EVP_sha256())) {
        SATR_INFO("Sign device certificate failed.");
        return false;
    }
    BIO *device_certificate = BIO_new_file(getDeviceCertificatePath(), "w");
    if (PEM_write_bio_X509(device_certificate, new_certificate) != 1) {
        SATR_ERROR("Save device certificate file failed.");
        return false;
    }
    BIO_free(device_certificate);
    X509_free(new_certificate);
    X509_free(ca_certificate_pem);
    X509_REQ_free(device_csr_pem);
    EVP_PKEY_free(ca_private_key_pem);
    BIO_free(ca_certificate);
    BIO_free(ca_private_key);
    
    FILE *fp1 = fopen(getDeviceCertificatePath(), "a+");
    FILE *fp2 = fopen(getCACertifcatePath(), "r");
    char buffer[256];
    while (fgets(buffer, sizeof(buffer), fp2)) {
        fprintf(fp1, "%s", buffer);
    }
    fclose(fp1);
    fclose(fp2);
    
    return true;
}

int x509AddExtension(X509 *cert, int nid, char *value) {
    X509_EXTENSION *extension;
    X509V3_CTX ctx;
    X509V3_set_ctx_nodb(&ctx);
    X509V3_set_ctx(&ctx, cert, cert, NULL, NULL, 0);
    extension = X509V3_EXT_conf_nid(NULL, &ctx, nid, value);
    if (!extension) {
        printf("%s\n", "add extension error");
        return 0;
    }
    X509_add_ext(cert, extension, -1);
    X509_EXTENSION_free(extension);
    return 1;
}

bool generateDeviceCertificate(char *name) {
    if (hasCACertificateFile() == false || hasCAPrivateKeyFile() == false) {
        SATR_ERROR("ca.cert.pem or ca.private_key.pem not founded.");
        return false;
    }
    char thing_name[50];
    if (strlen(name) > 50) {
        SATR_ERROR("Device name length must less than 50.");
        return false;
    }
    if (strcmp(name, "auto") == 0) {
        strcpy(thing_name, "sensor.live");
    } else {
        strcpy(thing_name, name);
    }
    if (hasDevicePublicKey() == true && hasDevicePrivateKey() == true) {
        SATR_INFO("Device public/private key already exists");
        if (hasDeviceCsr() == false) {
            SATR_INFO("Start to generate device csr");
            _generateDeviceCsr(thing_name);
        }
    } else {
        SATR_INFO("Start to generate device key pair");
        if (_generateDeviceKeyPair() == false) {
            return false;
        }
        SATR_INFO("Generate device key pair success.");
        SATR_INFO("Start to generate device csr");
        if (_generateDeviceCsr(thing_name) == false) {
            return false;
        }
    }
    SATR_INFO("Start to generate device certificate");
    _generateDeviceCertificate();
    return true;
}

char *getThingName() {
    BIO *device_certificate = BIO_new(BIO_s_file());
    BIO_read_filename(device_certificate, getDeviceCertificatePath());
    X509 *device_certificae_pem = PEM_read_bio_X509(device_certificate, NULL, 0, NULL);
    if (!device_certificae_pem) {
        SATR_ERROR("The device certificate file isn't exists.");
        return "";
    }
    char *thing_name;
    char common_name[50];
    X509_NAME_get_text_by_NID(X509_get_subject_name(device_certificae_pem), NID_commonName, common_name, 256);
    if (strcmp(common_name, "sensor.live") != 0) {
        thing_name = malloc(strlen(common_name));
        strcpy(thing_name, common_name);
        return thing_name;
    }
    FILE *fp = fopen(getDeviceCertificatePath(), "r");
    char line[256];
    char pem[2500];
    while (fgets(line, sizeof(line), fp)) {
        if (strcmp(line, "-----BEGIN CERTIFICATE-----\n") == 0) {
        } else if (strcmp(line, "-----END CERTIFICATE-----\n") == 0) {
            break;
        } else {
            strncat(pem, line, strlen(line) - 1);
        }
    }
    fclose(fp);
    const size_t thing_name_size = 40;
    const size_t size = 2000;
    char base64_pem[size];
    size_t base64_pem_length = base64Decode(pem, base64_pem);
    char *hex_pem = bin2hex((unsigned char *)base64_pem, base64_pem_length);
    char *prefix = "301d0603551d0e04160414";
    char *find_prefix = strstr(hex_pem, prefix);
    if (find_prefix) {
        thing_name = malloc(thing_name_size);
        strncpy(thing_name, find_prefix + strlen(prefix), thing_name_size);
        thing_name[thing_name_size] = 0;
    } else {
        SATR_ERROR("Can't get the thing name.");
        abort();
    }
    return thing_name;
}

char *bin2hex(const unsigned char *bin, size_t length) {
    char *output;
    size_t i;
    if (bin == NULL || length == 0) {
        return NULL;
    }
    output = malloc(length*2+1);
    for (i=0; i<length; i++) {
        output[i*2]   = "0123456789abcdef"[bin[i] >> 4];
        output[i*2+1] = "0123456789abcdef"[bin[i] & 0x0F];
    }
    output[length*2] = '\0';
 
    return output;
}

size_t base64Decode(const char* input, char* output)
{
    base64_decodestate s;
    size_t cnt;

    base64_init_decodestate(&s);
    cnt = base64_decode_block(input, strlen(input), output, &s);
    output[cnt] = 0;

    return cnt;
}

int base64_decode_value(char value_in)
{
    static const char decoding[] = {62,-1,-1,-1,63,52,53,54,55,56,57,58,59,60,61,-1,-1,-1,-2,-1,-1,-1,0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,-1,-1,-1,-1,-1,-1,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,41,42,43,44,45,46,47,48,49,50,51};
    static const char decoding_size = sizeof(decoding);
    value_in -= 43;
    if (value_in < 0 || value_in > decoding_size) {
        return -1;
    }
    return decoding[(int)value_in];
}

void base64_init_decodestate(base64_decodestate *state_in)
{
    state_in->step = step_a;
    state_in->plainchar = 0;
}

int base64_decode_block(const char *code_in, const int length_in, char *plaintext_out, base64_decodestate *state_in)
{
    const char* codechar = code_in;
    char* plainchar = plaintext_out;
    char fragment;
    *plainchar = state_in->plainchar;
    switch (state_in->step) {
        while (1){
            case step_a:
                do {
                    if (codechar == code_in+length_in) {
                        state_in->step = step_a;
                        state_in->plainchar = *plainchar;
                        return plainchar - plaintext_out;
                    }
                    fragment = (char)base64_decode_value(*codechar++);
                } while (fragment < 0);
                *plainchar = (fragment & 0x03f) << 2;
            case step_b:
                do {
                    if (codechar == code_in+length_in) {
                        state_in->step = step_b;
                        state_in->plainchar = *plainchar;
                        return plainchar - plaintext_out;
                    }
                    fragment = (char)base64_decode_value(*codechar++);
                } while (fragment < 0);
                *plainchar++ |= (fragment & 0x030) >> 4;
                *plainchar = (fragment & 0x00f) << 4;
            case step_c:
                do {
                    if (codechar == code_in+length_in) {
                        state_in->step = step_c;
                        state_in->plainchar = *plainchar;
                        return plainchar - plaintext_out;
                    }
                    fragment = (char)base64_decode_value(*codechar++);
                } while (fragment < 0);
                *plainchar++ |= (fragment & 0x03c) >> 2;
                *plainchar    = (fragment & 0x003) << 6;
            case step_d:
                do {
                    if (codechar == code_in + length_in) {
                    state_in->step = step_d;
                    state_in->plainchar = *plainchar;
                    return plainchar - plaintext_out;
                }
                fragment = (char)base64_decode_value(*codechar++);
        } while (fragment < 0);
            *plainchar++ |= (fragment & 0x03f);
        }
    }
    return plainchar - plaintext_out;
}