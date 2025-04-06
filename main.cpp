// FIDO2 Authentication Queue System
// This implementation uses libfido2 for WebAuthn/FIDO2 authentication

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

#include "HumanVerificationQueue.h"

// Example usage
int main() {
    HumanVerificationQueue queue;
    
    // Start processing queue with a lambda function
    queue.startProcessing([](const std::string& userId) {
        std::cout << "Processing user: " << userId << std::endl;
    });
    
    // Simulate users trying to join the queue
    std::cout << "Simulating users joining queue..." << std::endl;
    queue.enqueueUser("user1");
    
    // Wait a bit to let processing happen
    std::this_thread::sleep_for(std::chrono::seconds(5));
    
    // Check queue stats
    std::cout << "Queue size: " << queue.getQueueSize() << std::endl;
    std::cout << "Verified users: " << queue.getVerifiedUsersCount() << std::endl;
    
    // Cleanup
    queue.stopProcessing();
    
    return 0;
}