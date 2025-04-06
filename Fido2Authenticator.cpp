#include <iostream>
#include <queue>
#include <mutex>
#include <condition_variable>
#include <thread>
#include <chrono>
#include <map>
#include <string>
#include <functional>
#include <fido.h>
#include <vector>
#include <cstring>
#include <cstdlib>
#include <cassert>
#include "Fido2Authenticator.h"

Fido2Authenticator::Fido2Authenticator() : device(nullptr), initialized(false) {
            // Initialize libfido2
            fido_init(FIDO_DEBUG);
            initialized = true;
        }
    
Fido2Authenticator::~Fido2Authenticator() {
    if (device) {
        fido_dev_close(device);
        fido_dev_free(&device);
    }
}

bool Fido2Authenticator::findDevice() {
    fido_dev_info_t* dev_info;
    size_t dev_count;
    int r;

    dev_info = fido_dev_info_new(1);
    if (!dev_info) {
        std::cerr << "Error allocating device info" << std::endl;
        return false;
    }

    r = fido_dev_info_manifest(dev_info, 1, &dev_count);
    if (r != FIDO_OK) {
        std::cerr << "Error discovering devices: " << fido_strerr(r) << std::endl;
        fido_dev_info_free(&dev_info, 1);
        return false;
    }

    if (dev_count == 0) {
        std::cerr << "No FIDO2 devices found" << std::endl;
        fido_dev_info_free(&dev_info, 1);
        return false;
    }

    // Open the first device
    const fido_dev_info_t* di = fido_dev_info_ptr(dev_info, 0);
    device = fido_dev_new();
    if (!device) {
        std::cerr << "Error allocating device" << std::endl;
        fido_dev_info_free(&dev_info, 1);
        return false;
    }

    r = fido_dev_open(device, fido_dev_info_path(di));
    fido_dev_info_free(&dev_info, 1);
    
    if (r != FIDO_OK) {
        std::cerr << "Error opening device: " << fido_strerr(r) << std::endl;
        fido_dev_free(&device);
        device = nullptr;
        return false;
    }

    return true;
}

bool Fido2Authenticator::verifyUser(const std::string& userId, const std::string& challenge) {
    if (!device) {
        if (!findDevice()) {
            return false;
        }
    }

    // Convert challenge to byte array
    std::vector<unsigned char> challengeBytes(challenge.begin(), challenge.end());
    
    // Create assertion
    fido_assert_t* assert = fido_assert_new();
    if (!assert) {
        std::cerr << "Error creating assertion" << std::endl;
        return false;
    }

    // Set parameters for the assertion
    int r = fido_assert_set_clientdata_hash(assert, challengeBytes.data(), challengeBytes.size());
    if (r != FIDO_OK) {
        std::cerr << "Error setting client data hash: " << fido_strerr(r) << std::endl;
        fido_assert_free(&assert);
        return false;
    }

    // Set relying party
    r = fido_assert_set_rp(assert, "example.com");
    if (r != FIDO_OK) {
        std::cerr << "Error setting relying party: " << fido_strerr(r) << std::endl;
        fido_assert_free(&assert);
        return false;
    }

    // Allow user verification
    r = fido_assert_set_uv(assert, FIDO_OPT_TRUE);
    if (r != FIDO_OK) {
        std::cerr << "Error setting user verification: " << fido_strerr(r) << std::endl;
        fido_assert_free(&assert);
        return false;
    }

    // Perform the assertion
    r = fido_dev_get_assert(device, assert, nullptr);
    if (r != FIDO_OK) {
        std::cerr << "Error performing assertion: " << fido_strerr(r) << std::endl;
        fido_assert_free(&assert);
        return false;
    }

    // Verify the assertion
    size_t auth_count = fido_assert_count(assert);
    bool verified = false;
    
    if (auth_count > 0) {
        // In a real app, you would verify the signature, user ID, etc.
        // For this example, we're just checking if authentication succeeded
        verified = true;
        std::cout << "Authentication successful for user " << userId << std::endl;
    }

    fido_assert_free(&assert);
    return verified;
}