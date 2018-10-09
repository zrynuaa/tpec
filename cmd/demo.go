package main

import (
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"math/big"
	"os"
	"time"

	"github.com/btcsuite/btcd/btcec"
	"github.com/cfromknecht/tpec"
)

const (
	NPaillierBits  = 2048
	NthRootSecBits = 128
	RangeSecBits   = 40
)

var (
	nthRootSecBits = flag.Int("nthroot-soundness", NthRootSecBits,
		"bits of soundness in proving paillier key correctness")

	rangeSecBits = flag.Int("range-soundness", RangeSecBits,
		"bits of soundness in paillier-ciphertext range proof")

	message = flag.String("message", "",
		"text string to sign, computes signature over SHA256(msg)")

	digest = flag.String("digest", "",
		"hexidecimal representation of a hash of a message to sign")
)

func fail(str string, args ...interface{}) {
	flag.Usage()
	fmt.Printf(str+"\n", args...)
	os.Exit(1)
}

func getDigest() tpec.Uint256 {
	var dgst tpec.Uint256
	switch {
	case len(*message) > 0 && len(*digest) > 0:
		fail("either -message or -digest should be set, not both")

	case len(*message) > 0:
		fmt.Printf("Message: \"%s\"\n", *message)
		dgst = sha256.Sum256([]byte(*message))

	case len(*digest) > 0:
		dgstBytes, err := hex.DecodeString(*digest)
		if err != nil {
			fail("unable to decode hex string: %v", err)
		}

		if len(dgstBytes) != len(dgst) {
			fail("digest is %d bytes, should be %d",
				len(dgstBytes), len(dgst))
		}

		copy(dgst[:], dgstBytes)
	default:
		fail("either -message or -digest must be specified")
	}

	return dgst
}

func main() {
	flag.Parse()

	params := btcec.S256().CurveParams
	q := new(big.Int).Set(params.N)
	q3 := new(big.Int).Div(q, big.NewInt(3))
	qSquared := new(big.Int).Mul(q, q)

	cfg := tpec.Config{
		Q:              q,
		Q3:             q3,
		QSquared:       qSquared,
		NPaillierBits:  NPaillierBits,
		NthRootSecBits: *nthRootSecBits,
		RangeSecBits:   *rangeSecBits,
	}

	fmt.Printf("KeyGen parameters:\n")
	fmt.Printf("  paillier key bits:        %d\n", cfg.NPaillierBits)
	fmt.Printf("  nth-root proof soundness: %d\n", cfg.NthRootSecBits)
	fmt.Printf("  range proof soundness:    %d\n", cfg.RangeSecBits)

	dgst := getDigest()
	fmt.Printf("Digest: %x\n", dgst)

	var p1 = tpec.NewParty1(&cfg)
	var p2 = tpec.NewParty2(&cfg)

	keyGenStart := time.Now()
	fmt.Printf("KEYGEN...")
	sk1, err := p1.GenKey(p2, nil, nil)
	if err != nil {
		fail("unable to generate 2p-ecdsa key: %v", err)
	}
	fmt.Printf(" DONE: %v\n", time.Since(keyGenStart))

	sk2, err := p2.PrivateKey()
	if err != nil {
		fail("unable to generate 2p-ecdsa key: %v", err)
	}

	fmt.Printf("x1: %x\n", *sk1.X1SK)
	fmt.Printf("x2: %x\n", *sk2.X2SK)
	fmt.Printf("Q: %x\n", sk1.PublicKey.SerializeCompressed())

	signStart := time.Now()
	fmt.Printf("SIGN...")
	sig, err := sk1.Sign(dgst[:], sk2)
	if err != nil {
		fail("unable to create 2p-ecdsa signature: %v", err)
	}
	fmt.Printf(" DONE: %v\n", time.Since(signStart))

	fmt.Printf("Signature:\n")
	fmt.Printf("  R: %x\n", sig.R)
	fmt.Printf("  S: %x\n", sig.S)

	valid1 := sig.Verify(dgst[:], sk1.PublicKey)
	valid2 := sig.Verify(dgst[:], sk2.PublicKey)

	fmt.Printf("Is valid under Q?: %v\n", valid1 && valid2)

	os.Exit(0)
}
