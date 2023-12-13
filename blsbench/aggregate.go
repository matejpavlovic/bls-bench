package main

import (
	"crypto/rand"
	"fmt"
	"slices"

	"github.com/drand/kyber"
	bls12381 "github.com/drand/kyber-bls12381"
	"github.com/drand/kyber/sign/bls"
	"github.com/drand/kyber/util/random"
	"github.com/spf13/cobra"
)

var (
	numSigs      []int
	aggregateCmd = &cobra.Command{
		Use:   "aggregate",
		Short: "benchmark aggregate signatures",
		RunE: func(cmd *cobra.Command, args []string) error {
			return benchmarkAggregate()
		},
	}
)

func init() {
	aggregateCmd.Flags().IntSliceVarP(&numSigs, "num-sigs", "n", []int{1, 10, 100, 1000}, "Number of signatures to aggregate. Can be specified multiple times.")
	rootCmd.AddCommand(aggregateCmd)
}

func benchmarkAggregate() error {

	fmt.Printf("----------------------\n")
	fmt.Printf("      Payload to sign: %d bytes\n", dataSize)
	fmt.Printf("   Benchmark duration: %s\n", benchDuration)
	fmt.Printf("Numbers of signatures: %v\n", numSigs)
	fmt.Printf("----------------------\n")
	fmt.Println("Initializing...")

	// Initialize all variables.
	msgData := make([]byte, dataSize)
	nBytes, err := rand.Read(msgData)
	if err != nil {
		panic(err)
	}
	if nBytes != dataSize {
		panic(fmt.Errorf("only read %d random bytes, but data size is %d", nBytes, dataSize))
	}
	//randomness := random.New(prand.New(prand.NewSource(123)))
	randSource := random.New(rand.Reader)
	suite := bls12381.NewBLS12381Suite()
	schemeOnG1 := bls.NewSchemeOnG1(suite)
	schemeOnG2 := bls.NewSchemeOnG2(suite)

	maxN := slices.Max(numSigs)
	privKeysOnG1 := make([]kyber.Scalar, maxN)
	privKeysOnG2 := make([]kyber.Scalar, maxN)
	pubKeysOnG1 := make([]kyber.Point, maxN)
	pubKeysOnG2 := make([]kyber.Point, maxN)
	sigsOnG1 := make([][]byte, maxN)
	sigsOnG2 := make([][]byte, maxN)
	for i := 0; i < maxN; i++ {
		privKeysOnG1[i], pubKeysOnG1[i] = schemeOnG1.NewKeyPair(randSource)
		sigsOnG1[i], err = schemeOnG1.Sign(privKeysOnG1[i], msgData)
		if err != nil {
			panic(err)
		}
		privKeysOnG2[i], pubKeysOnG2[i] = schemeOnG2.NewKeyPair(randSource)
		sigsOnG2[i], err = schemeOnG2.Sign(privKeysOnG2[i], msgData)
		if err != nil {
			panic(err)
		}
	}

	fmt.Printf("       Signatures on: %15s %15s\n", "G1 (ops/s)", "G2 (ops/s)")

	for _, n := range numSigs {
		fmt.Printf("Aggregate %5d keys: ", n)
		fmt.Printf("%15.2f ", runFor(benchDuration, func() {
			_ = schemeOnG1.AggregatePublicKeys(pubKeysOnG1[:n]...)
		}))
		fmt.Printf("%15.2f\n", runFor(benchDuration, func() {
			_ = schemeOnG2.AggregatePublicKeys(pubKeysOnG2[:n]...)
		}))
	}

	for _, n := range numSigs {
		fmt.Printf("Aggregate %5d sigs: ", n)
		fmt.Printf("%15.2f ", runFor(benchDuration, func() {
			_, err = schemeOnG1.AggregateSignatures(sigsOnG1[:n]...)
			if err != nil {
				panic(err)
			}
		}))
		fmt.Printf("%15.2f\n", runFor(benchDuration, func() {
			_, err = schemeOnG2.AggregateSignatures(sigsOnG2[:n]...)
			if err != nil {
				panic(err)
			}
		}))
	}

	fmt.Printf("              Keygen: ")
	fmt.Printf("%15.2f ", runFor(benchDuration, func() {
		_, _ = schemeOnG1.NewKeyPair(randSource)
	}))
	fmt.Printf("%15.2f\n", runFor(benchDuration, func() {
		_, _ = schemeOnG2.NewKeyPair(randSource)
	}))

	fmt.Printf("                Sign: ")
	fmt.Printf("%15.2f ", runFor(benchDuration, func() {
		_, err = schemeOnG1.Sign(privKeysOnG1[0], msgData)
		if err != nil {
			panic(err)
		}
	}))
	fmt.Printf("%15.2f\n", runFor(benchDuration, func() {
		_, err = schemeOnG2.Sign(privKeysOnG2[0], msgData)
		if err != nil {
			panic(err)
		}
	}))

	fmt.Printf("              Verify: ")
	fmt.Printf("%15.2f ", runFor(benchDuration, func() {
		err = schemeOnG1.Verify(pubKeysOnG1[0], msgData, sigsOnG1[0])
		if err != nil {
			panic(err)
		}
	}))
	fmt.Printf("%15.2f\n", runFor(benchDuration, func() {
		err = schemeOnG2.Verify(pubKeysOnG2[0], msgData, sigsOnG2[0])
		if err != nil {
			panic(err)
		}
	}))

	return nil
}
