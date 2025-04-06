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

class Fido2Authenticator {
    private:
        fido_dev_t* device;
        bool initialized;
    
    public:
        Fido2Authenticator() ;
    
        ~Fido2Authenticator();
    
        bool findDevice();

        bool verifyUser(const std::string& userId, const std::string& challenge);
    };