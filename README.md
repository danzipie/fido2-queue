## Queue users with FIDO2 attestation

Implements a queue where users are asked to attest a message
using FIDO2.

## Requirements

Fido2 library.

## Quick start

On MacOS, install the library:

´´´
brew install libfido2
´´´

´´´
g++ -std=c++11 -o fido2_queue main.cpp HumanVerificationQueue.cpp Fido2Authenticator.cpp  -I/opt/homebrew/include -L/opt/homebrew/lib -lfido2
´´´
