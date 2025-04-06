#ifndef HUMANVERIFICATIONQUEUE_H
#define HUMANVERIFICATIONQUEUE_H

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

#include "Fido2Authenticator.h"

class HumanVerificationQueue {

    private:
    Fido2Authenticator authenticator;
    std::queue<std::string> userQueue;
    std::map<std::string, bool> verifiedUsers;
    std::mutex queueMutex;
    std::condition_variable cv;
    bool processingActive;
    std::thread processingThread;

    public:
        HumanVerificationQueue();

        ~HumanVerificationQueue();
    
        void enqueueUser(const std::string& userId);
    
        void startProcessing(std::function<void(const std::string&)> processFunc);

        void stopProcessing();
    
        size_t getQueueSize();
    
        size_t getVerifiedUsersCount();
    };

#endif // HUMANVERIFICATIONQUEUE_H