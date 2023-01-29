# Sealed-Bid Blockchain Auctions using F3B

## Project Description

This project implements a traditional and F3B sealed-bid blockchain auction on EPFL Decentralized and Distributed Computing Laboratory's Dela using Flash Freezing Flash Boys (F3B).  In sealed-bid auctions, all bidders submit secret bids during the bidding period. When the bidding period is complete, the bids are unsealed and the highest bidder is declared the winner.

### Traditional Auction Description
In the traditional auction, each bidder submits a bid transaction during the bidding period and a reveal transaction during the reveal period. The bid transaction consists of both a commit and deposit. The bidder’s commit is the SHA256 hash of the bid and a chosen random nonce. The bidder’s deposit is a payment at least as large as the bid itself.The reveal transaction consists of the bid and random nonce. 

During the bidding period, the auction smart contract stores the bidder’s commit and deposit. During the reveal period, the auction smart contract checks that each reveal matches its corresponding bid and stores the matching reveals. When the reveal period is complete, the auction smart contract selects the highest bidder as the winner and refunds the deposit of each losing bidder. 

### F3B Auction Description
In the F3B Auction, each bidder submits an encrypted bid transaction that is stored on the blockchain. This encrypted bid transaction consists only of the bid, which is transferred to the auction smart contract if it is the highest bid. When the bidding period is complete, the secret-management committee releases the decryption keys for each bid transaction, and the bid transactions are decrypted and executed. The auction smart contract then receives the executed bid transactions. The auction smart contract stores the bid of the highest bidder and does not accept bids of lower bidders. Thus, when a higher bid is received, the auction smart contract stores this new highest bid and bidder and refunds the bid from the previous highest bidder.

## Project Files

The project folder structure and files are outlined below:
* contracts
    * bank
        * mod.go: Implementation of bank smart contract
        * mod_test.go: Unit testing of bank smart contract
        * controller
            * mod.go: Controller for bank smart contract
            * mod_test.go: Unit testing of controller
    * auction
        * mod.go: Implementation of traditional auction smart contract
        * mod_test.go: Unit testing of traditional auction smart contract
        * controller
            * mod.go: Controller for traditional auction smart contract
            * mod_test.go: Unit testing of controller
    * auctionF3B
        * mod.go: Implementation of F3B auction smart contract
        * mod_test.go: Unit testing of F3B auction smart contract
        * controller
            * mod.go: Controller for F3B auction smart contract
            * mod_test.go: Unit testing of controller
* dkg
    * pederson: Mahsa Bastankhah's implementation of F3B
* test
    * SymmetricEncrypt_test.go: Implementation of AES encryption and decryption.
    * TraditionalAuction_test.go: Integration testing for the traditional auction system
    * TraditionalAuction_evaluation\textunderscore test.go: Latency and Throughput evaluation of the traditional auction system
    * F3BAuction_test.go: Integration testing for the F3B auction system
    * F3BAuction_evaluation_test.go: Latency and Throughput evaluation of the F3B auction system
    * F3B_test: Mahsa Bastankhah's implementation of F3B

## Project Setup

1: Install [Go](https://go.dev/dl/) v1.18.

2: Install the `crypto` utility from Dela:

```sh
git clone https://github.com/dedis/dela.git
cd dela/cli/crypto
go install
```

Go will install the binaries in `$GOPATH/bin`, so be sure this it is correctly
added to you path (e.g. `export PATH=$PATH:/Users/username/go/bin`).

## Run Traditional and F3B Sealed-Bid Blockchain Auctions

For the traditional sealed-bid blockchain auction, a sample auction can be run in test/TraditionalAuction_test.go. For the F3B sealed-bid blockchain auction, a sample auction can be run in test/F3BAuction_test.go.
