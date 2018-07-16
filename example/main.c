#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "../src/things_registry.h"

int main(int argc, char **argv) {
    if (hasDeviceCertificate() == 0) {
        SATR_INFO("Device certificate files not exists.");
        if (generateDeviceCertificate("auto")) {
            SATR_INFO("Device certificate generated.");
        } else {
            SATR_ERROR("Device certificate generate failed.");
        }
    } else {
        SATR_INFO("Device certificate files is ready.");
    }
    char *thing_name = getThingName();
    SATR_INFO(thing_name);
}