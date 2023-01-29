package integration

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	_ "net/http/pprof"

	"github.com/stretchr/testify/require"
	accessContract "go.dedis.ch/dela/contracts/access"
	"go.dedis.ch/dela/core/txn"
	"go.dedis.ch/dela/core/txn/signed"
	"go.dedis.ch/dela/crypto"
	"go.dedis.ch/dela/crypto/bls"
	"go.dedis.ch/dela/crypto/loader"
	"go.dedis.ch/dela/dkg"
	"go.dedis.ch/dela/dkg/pedersen"
	"go.dedis.ch/dela/dkg/pedersen/types"
	"go.dedis.ch/dela/serde/json"
	"golang.org/x/xerrors"

	"go.dedis.ch/dela/mino"

	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/suites"
	"go.dedis.ch/kyber/v3/xof/keccak"
)

func init() {
	rand.Seed(0)
}

func Test_F3BAuction_Correctness(t *testing.T) {

	// SETUP VARIABLES
	// batch size => the number of scenarios we run
	// numDKGs => smc size
	// numNodes => number of DELA nodes
	batchSizes := []int{10}
	numDKGs := []int{8}
	withGrpc := false
	numNodes := 3

	// Run testscenario for number of batches, number of SMC Nodes
	for _, batchSize := range batchSizes {
		for _, numDKG := range numDKGs {
			t.Run(fmt.Sprintf("batch size %d num dkg %d", batchSize, numDKG),
				f3b_Auction_Correctness(batchSize, numDKG, numNodes, withGrpc))
		}
	}
}

// Tests the F3B Auction scenario
func f3b_Auction_Correctness(batchSize, numDKG, numNodes int, withGrpc bool) func(t *testing.T) {
	return func(t *testing.T) {

		require.Greater(t, numDKG, 0)
		require.Greater(t, numNodes, 0)
		require.GreaterOrEqual(t, numDKG, numNodes)

		to := time.Second * 10 // transaction inclusion timeout

		// set up the minos
		minosBuilder := getMinoch
		if withGrpc {
			minosBuilder = getMinogRPCs
		}

		minos := minosBuilder(t, numDKG)
		dkgs := make([]dkg.DKG, numDKG)
		addrs := make([]mino.Address, numDKG)

		// initializing the addresses
		for i, mino := range minos {
			addrs[i] = mino.GetAddress()
		}

		// Create public keys for each node
		pubkeys := make([]kyber.Point, len(minos))

		for i, mino := range minos {
			dkg, pubkey := pedersen.NewPedersen(mino)
			dkgs[i] = dkg
			pubkeys[i] = pubkey
		}

		// used to setup dkg with collective authority, encrypt/decrypt functionality
		actors := make([]dkg.Actor, numDKG)
		for i := 0; i < numDKG; i++ {
			actor, err := dkgs[i].Listen()
			require.NoError(t, err)
			actors[i] = actor
		}

		// Creates new collective authority
		fakeAuthority := NewAuthority(addrs, pubkeys)
		_, err := actors[0].Setup(fakeAuthority, numDKG)
		require.NoError(t, err)

		// setting up the blockchain

		dir, err := os.MkdirTemp("", "dela-integration-test")
		require.NoError(t, err)

		t.Logf("using temps dir %s", dir)

		defer os.RemoveAll(dir)

		nodes := make([]dela, numNodes)

		for i := range nodes {
			nodes[i] = newDelaNode(t, filepath.Join(dir, fmt.Sprintf("node%d", i)), 0)
		}

		nodes[0].Setup(nodes[1:]...)

		l := loader.NewFileLoader(filepath.Join(dir, "private.key"))

		// creating a new client/signer
		signerdata, err := l.LoadOrCreate(newKeyGenerator())
		require.NoError(t, err)

		signer, err := bls.NewSignerFromBytes(signerdata)
		require.NoError(t, err)

		pubKey := signer.GetPublicKey()
		pubKeyText, _ := pubKey.MarshalText()
		pubKeyString := string(pubKeyText)
		cred := accessContract.NewCreds(aKey[:])

		for _, node := range nodes {
			node.GetAccessService().Grant(node.(cosiDelaNode).GetAccessStore(), cred, pubKey)
		}

		manager := signed.NewManager(signer, &txClient{})

		pubKeyBuf, err := signer.GetPublicKey().MarshalBinary()
		require.NoError(t, err)

		// sending the value contract grant transaction to the blockchain
		args := []txn.Arg{
			{Key: "go.dedis.ch/dela.ContractArg", Value: []byte("go.dedis.ch/dela.Access")},
			{Key: "access:grant_id", Value: []byte(hex.EncodeToString(valueAccessKey[:]))},
			{Key: "access:grant_contract", Value: []byte("go.dedis.ch/dela.Value")},
			{Key: "access:grant_command", Value: []byte("all")},
			{Key: "access:identity", Value: []byte(base64.StdEncoding.EncodeToString(pubKeyBuf))},
			{Key: "access:command", Value: []byte("GRANT")},
		}
		// waiting for the confirmation of the transaction
		err = addAndWait(t, to, manager, nodes[0].(cosiDelaNode), args...)
		require.NoError(t, err)

		// Giving access to auctionF3B contract
		args = []txn.Arg{
			{Key: "go.dedis.ch/dela.ContractArg", Value: []byte("go.dedis.ch/dela.Access")},
			{Key: "access:grant_id", Value: []byte(hex.EncodeToString(valueAccessKey[:]))},
			{Key: "access:grant_contract", Value: []byte("go.dedis.ch/dela.AuctionF3B")},
			{Key: "access:grant_command", Value: []byte("all")},
			{Key: "access:identity", Value: []byte(base64.StdEncoding.EncodeToString(pubKeyBuf))},
			{Key: "access:command", Value: []byte("GRANT")},
		}
		err = addAndWait(t, to, manager, nodes[0].(cosiDelaNode), args...)
		require.NoError(t, err)

		// AUCTION INIT COMMAND
		fmt.Println("BATCH SIZE: ", fmt.Sprint(batchSize))
		bidLength := []byte(fmt.Sprint(batchSize))
		args = []txn.Arg{
			{Key: "go.dedis.ch/dela.ContractArg", Value: []byte("go.dedis.ch/dela.AuctionF3B")},
			{Key: "value:initBidLength", Value: bidLength},
			{Key: "value:command", Value: []byte("INIT")},
		}
		err = addAndWait(t, to, manager, nodes[0].(cosiDelaNode), args...)
		require.NoError(t, err)
		// Check Bid Length set correctly
		initBidKey := []byte("auction:bid_length")
		proof, err := nodes[0].GetOrdering().GetProof(initBidKey)
		require.NoError(t, err)
		require.Equal(t, bidLength, proof.GetValue())

		// creating GBar. we need a generator in order to follow the encryption and
		// decryption protocol of https://arxiv.org/pdf/2205.08529.pdf / we take an
		// agreed data among the participants and embed it as a point. the result is
		// the generator that we are seeking
		var suite = suites.MustFind("Ed25519")
		agreedData := make([]byte, 32)
		_, err = rand.Read(agreedData)
		require.NoError(t, err)
		gBar := suite.Point().Embed(agreedData, keccak.New(agreedData))

		// creating the symmetric keys in batch. we process the transactions in
		// batch to increase the throughput for more information refer to
		// https://arxiv.org/pdf/2205.08529.pdf / page 6 / step 1 (write
		// transaction)

		// write transaction arguments
		argSlice := make([][]txn.Arg, batchSize)

		var ciphertexts []types.Ciphertext

		// generate symmetric keys to be encrypted
		keys := make([][29]byte, batchSize)
		for i := range keys {
			_, err = rand.Read(keys[i][:])
			require.NoError(t, err)
		}

		// Create a Write instance
		for i := 0; i < batchSize; i++ {
			// Encrypting the symmetric key with PKsmc
			ciphertext, remainder, err := actors[0].VerifiableEncrypt(keys[i][:], gBar)
			require.NoError(t, err)
			require.Len(t, remainder, 0)

			ciphertexts = append(ciphertexts, ciphertext)

			// converting the kyber.Point or kyber.Scalar to bytes
			Cbytes, err := ciphertext.C.MarshalBinary()
			require.NoError(t, err)
			Ubytes, err := ciphertext.K.MarshalBinary()
			require.NoError(t, err)
			Ubarbytes, err := ciphertext.UBar.MarshalBinary()
			require.NoError(t, err)
			Ebytes, err := ciphertext.E.MarshalBinary()
			require.NoError(t, err)
			Fbytes, err := ciphertext.F.MarshalBinary()
			require.NoError(t, err)

			// Put all the data together
			// Ck is the encrypted symmetric key
			Ck := append(Cbytes[:], Ubytes[:]...)
			Ck = append(Ck, Ubarbytes[:]...)
			Ck = append(Ck, Ebytes[:]...)
			Ck = append(Ck, Fbytes[:]...)

			// WRITE 1: Write Ck
			// creating the transaction to write Ck, make sure written correctly
			thisCkKey := []byte(fmt.Sprintf("Ck:%s", fmt.Sprint(i)))
			argSlice[i] = getWriteArgs(thisCkKey, Ck)
			// Make sure value tx did not yield error
			err = addAndWait(t, to, manager, nodes[0].(cosiDelaNode), argSlice[i]...)
			require.NoError(t, err)
			// Make sure value tx correct
			proof, err := nodes[0].GetOrdering().GetProof(thisCkKey)
			require.NoError(t, err)
			require.Equal(t, Ck, proof.GetValue())

			// WRITE 2: Write encrypted bid TX
			// Create encrypted Bid TX
			bid := []byte(fmt.Sprint(i + 1))
			args = getBidArgs(bid)
			nonce := uint64(3 + (batchSize * 2) + (i * 3) + 2)
			aesKey := getAESKey(keys[i])
			etx := getEncryptedTX(t, nonce, signer, aesKey, args...)
			thisEtxKey := []byte(fmt.Sprintf("etx:%s", fmt.Sprint(i)))
			writeArgs := getWriteArgs(thisEtxKey, etx)
			// Make sure value tx did not yield error
			err = addAndWait(t, to, manager, nodes[0].(cosiDelaNode), writeArgs...)
			require.NoError(t, err)
			// Make sure value tx correct
			proof, err = nodes[0].GetOrdering().GetProof(thisEtxKey)
			require.NoError(t, err)
			require.Equal(t, etx, proof.GetValue())
		}

		// Read/Decrypt/Submit TX
		for i := 0; i < batchSize; i++ {
			// Read Ck
			// creating the transaction to read Ck
			thisCkKey := []byte(fmt.Sprintf("Ck:%s", fmt.Sprint(i)))
			readArgs := getReadArgs(thisCkKey)
			// Make sure value tx did not yield error
			err = addAndWait(t, to, manager, nodes[0].(cosiDelaNode), readArgs...)
			require.NoError(t, err)
			// Get Ck value
			proof, err := nodes[0].GetOrdering().GetProof(thisCkKey)

			// Decrypt Ck value
			decrypted, _, _, err := actors[0].VerifiableDecrypt([]types.Ciphertext{ciphertexts[i]})
			require.NoError(t, err)

			// make sure that the decryption was correct
			require.Equal(t, keys[i][:], decrypted[0])

			// Read Encrypted Bid TX
			thisEtxKey := []byte(fmt.Sprintf("etx:%s", fmt.Sprint(i)))
			readArgs = getReadArgs(thisEtxKey)
			// Make sure value tx did not yield error
			err = addAndWait(t, to, manager, nodes[0].(cosiDelaNode), readArgs...)
			require.NoError(t, err)
			// Get Encrypted TX value
			proof, err = nodes[0].GetOrdering().GetProof(thisEtxKey)
			etx := proof.GetValue()

			// Decrypt/Submit TX
			aesKey := getAESKey(keys[i])
			dtx := getDecryptedTX(etx, aesKey)
			err = addAndWaitTX(t, to, manager, nodes[0].(cosiDelaNode), dtx)
			require.NoError(t, err)
		}

		// Check Winner
		args = getSelectWinnerArgs()
		err = addAndWait(t, to, manager, nodes[0].(cosiDelaNode), args...)
		require.NoError(t, err)
		// Highest Bid
		highestBidKey := []byte("auction:highest_bid")
		proof, err = nodes[0].GetOrdering().GetProof(highestBidKey)
		require.NoError(t, err)
		require.Equal(t, strconv.Itoa(batchSize), string(proof.GetValue()))
		// Highest Bidder
		highestBidderKey := []byte("auction:highest_bidder")
		proof, err = nodes[0].GetOrdering().GetProof(highestBidderKey)
		require.NoError(t, err)
		require.Equal(t, pubKeyString, string(proof.GetValue()))
	}
}

// -----------------------------------------------------------------------------
// Utility functions

func makeTX(t *testing.T, nonce uint64, signer crypto.Signer, args ...txn.Arg) txn.Transaction {
	_, err := signer.GetPublicKey().MarshalBinary()
	options := []signed.TransactionOption{}
	for i := 0; i < len(args); i += 1 {
		options = append(options, signed.WithArg(args[i].Key, args[i].Value))
	}

	tx, err := signed.NewTransaction(nonce, signer.GetPublicKey(), options...)
	tx.Sign(signer)
	require.NoError(t, err)

	return tx
}

// Gets an encrypted tx from a signer and transaction args
// Transaction created and signed, then encrypted
func getEncryptedTX(t *testing.T, nonce uint64, signer crypto.Signer, key []byte, args ...txn.Arg) []byte {
	// Create tx
	tx := makeTX(t, nonce, signer, args...)

	// Encrypt tx with key
	ctx := json.NewContext()
	thisTXByte, _ := tx.Serialize(ctx)
	ct := symmetricEncrypt(thisTXByte, key)

	return ct
}

// Decrypts transaction with key
func getDecryptedTX(ct []byte, key []byte) txn.Transaction {
	// Decrypt tx
	dtx := symmetricDecrypt(ct, key)
	// Convert []byte to txn.Transaction
	ctx := json.NewContext()
	tx, _ := signed.NewTransactionFactory().TransactionOf(ctx, dtx)

	return tx
}

// Gets tx bid args given a bid
func getBidArgs(bid []byte) []txn.Arg {
	args := []txn.Arg{
		{Key: "go.dedis.ch/dela.ContractArg", Value: []byte("go.dedis.ch/dela.AuctionF3B")},
		{Key: "value:bid", Value: bid},
		{Key: "value:command", Value: []byte("BID")},
	}

	return args
}

// Gets tx write args given a key/value
func getWriteArgs(key []byte, val []byte) []txn.Arg {
	args := []txn.Arg{
		{Key: "go.dedis.ch/dela.ContractArg", Value: []byte("go.dedis.ch/dela.Value")},
		{Key: "value:key", Value: []byte(key)},
		{Key: "value:value", Value: []byte(val)},
		{Key: "value:command", Value: []byte("WRITE")},
	}

	return args
}

// Gets tx read args given a key
func getReadArgs(key []byte) []txn.Arg {
	args := []txn.Arg{
		{Key: "go.dedis.ch/dela.ContractArg", Value: []byte("go.dedis.ch/dela.Value")},
		{Key: "value:key", Value: []byte(key)},
		{Key: "value:command", Value: []byte("READ")},
	}

	return args
}

// Gets SelectWinner args
func getSelectWinnerArgs() []txn.Arg {
	args := []txn.Arg{
		{Key: "go.dedis.ch/dela.ContractArg", Value: []byte("go.dedis.ch/dela.AuctionF3B")},
		{Key: "value:command", Value: []byte("SELECTWINNER")},
	}

	return args
}

// Adds a signed tx
func addAndWaitTX(t *testing.T, to time.Duration, manager txn.Manager, node cosiDelaNode, tx txn.Transaction) error {
	manager.Sync()

	err := node.GetPool().Add(tx)
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), to)
	defer cancel()

	events := node.GetOrdering().Watch(ctx)

	for event := range events {
		for _, result := range event.Transactions {
			tx := result.GetTransaction()

			if bytes.Equal(tx.GetID(), tx.GetID()) {
				accepted, err := event.Transactions[0].GetStatus()
				require.Empty(t, err)

				require.True(t, accepted)
				return nil
			}
		}
	}

	return xerrors.Errorf("transaction not found")
}
