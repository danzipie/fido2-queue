#include "HumanVerificationQueue.h"

HumanVerificationQueue::HumanVerificationQueue() : processingActive(false) {}

HumanVerificationQueue::~HumanVerificationQueue() {
    stopProcessing();
}

void HumanVerificationQueue::enqueueUser(const std::string& userId) {
    std::unique_lock<std::mutex> lock(queueMutex);
    // Check if user is already verified
    if (verifiedUsers.find(userId) != verifiedUsers.end() && verifiedUsers[userId]) {
        std::cout << "User " << userId << " is already verified, adding directly to queue" << std::endl;
        userQueue.push(userId);
        cv.notify_one();
        return;
    }
    
    // User needs verification
    std::cout << "User " << userId << " needs verification before queueing" << std::endl;
    
    // Release lock during authentication to avoid blocking other operations
    lock.unlock();
    
    // Generate a challenge (in real app, this should be cryptographically secure)
    std::string challenge = "random_challenge_" + userId;
    
    // Perform FIDO2 authentication
    bool verified = authenticator.verifyUser(userId, challenge);
    
    lock.lock();
    if (verified) {
        verifiedUsers[userId] = true;
        userQueue.push(userId);
        cv.notify_one();
        std::cout << "User " << userId << " verified and added to queue" << std::endl;
    } else {
        std::cout << "User " << userId << " failed verification" << std::endl;
    }
}

void HumanVerificationQueue::startProcessing(std::function<void(const std::string&)> processFunc) {
    std::unique_lock<std::mutex> lock(queueMutex);
    if (processingActive) {
        return;
    }
    
    processingActive = true;
    lock.unlock();
    
    processingThread = std::thread([this, processFunc]() {
        while (true) {
            std::unique_lock<std::mutex> lock(queueMutex);
            
            // Wait until queue has users or processing is stopped
            cv.wait(lock, [this]() { 
                return !userQueue.empty() || !processingActive; 
            });
            
            if (!processingActive) {
                break;
            }
            
            // Process the next user in queue
            std::string userId = userQueue.front();
            userQueue.pop();
            
            // Release lock during processing
            lock.unlock();
            
            // Process the user
            processFunc(userId);
            
            // Small delay to simulate processing time
            std::this_thread::sleep_for(std::chrono::milliseconds(500));
        }
    });
}
    
void HumanVerificationQueue::stopProcessing() {
    {
        std::unique_lock<std::mutex> lock(queueMutex);
        processingActive = false;
        cv.notify_all();
    }
    
    if (processingThread.joinable()) {
        processingThread.join();
    }
}

size_t HumanVerificationQueue::getQueueSize() {
    std::unique_lock<std::mutex> lock(queueMutex);
    return userQueue.size();
}

size_t HumanVerificationQueue::getVerifiedUsersCount() {
    std::unique_lock<std::mutex> lock(queueMutex);
    return verifiedUsers.size();
}
    