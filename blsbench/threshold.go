package main

import (
	"crypto/rand"
	"fmt"

	"github.com/drand/kyber/util/random"
	tc "github.com/matejpavlovic/bls-bench/thresholdcrypto"
	"github.com/spf13/cobra"
)

var (
	numShares    []int
	g2Curve      bool
	thresholdCmd = &cobra.Command{
		Use:   "threshold",
		Short: "benchmark threshold signatures",
		RunE: func(cmd *cobra.Command, args []string) error {
			return benchmarkThreshold()
		},
	}
)

func init() {
	rootCmd.AddCommand(thresholdCmd)
	thresholdCmd.Flags().IntSliceVarP(&numShares, "num-shares", "n", []int{1, 10, 100, 1000}, "Number of signature shares. Can be specified multiple times.")
	thresholdCmd.Flags().BoolVarP(&g2Curve, "g2-curve", "g", false, "Use the G2 curve for signatures instead of G1.")
}

func benchmarkThreshold() error {

	// Initialize all variables.
	//randomness := random.New(prand.New(prand.NewSource(123)))
	randomness := random.New(rand.Reader)
	keys := make(map[int][]*tc.TBLSInst)
	shares := make(map[int][][]byte)
	sigs := make(map[int][]byte)
	curve := tc.G1
	if g2Curve {
		curve = tc.G2
	}

	fmt.Printf("----------------------\n")
	fmt.Printf("      Payload to sign: %d bytes\n", dataSize)
	fmt.Printf("   Benchmark duration: %s\n", benchDuration)
	fmt.Printf("Numbers of signatures: %v\n", numSigs)
	if curve == tc.G1 {
		fmt.Printf("  Signatures on curve: G1\n")
	} else {
		fmt.Printf("  Signatures on curve: G2\n")
	}
	fmt.Printf("----------------------\n")
	fmt.Println("Initializing...")

	// Generate random byte array as the message to be signed.
	msgData := make([]byte, dataSize)
	nBytes, err := rand.Read(msgData)
	if err != nil {
		panic(err)
	}
	if nBytes != dataSize {
		panic(fmt.Errorf("only read %d random bytes, but data size is %d", nBytes, dataSize))
	}
	msg := [][]byte{msgData}

	// Generate shared keys, shares, and signatures.
	for _, systemSize := range numShares {
		f := (systemSize - 1) / 3
		keys[systemSize] = tc.TBLS12381Keygen(2*f+1, nodeIDList(systemSize), randomness, curve)
		shares[systemSize] = make([][]byte, systemSize)
		for i := 0; i < systemSize; i++ {
			shares[systemSize][i], err = keys[systemSize][i].SignShare(msg)
			if err != nil {
				panic(err)
			}
		}
		sigs[systemSize], err = keys[systemSize][0].Recover(msg, shares[systemSize][:2*f+1])
	}

	fmt.Printf("    Number of nodes:")
	for _, systemSize := range numShares {
		fmt.Printf(" %12d ", systemSize)
	}
	fmt.Println()

	fmt.Printf("       Keygen ops/s:")
	for _, systemSize := range numShares {
		f := (systemSize - 1) / 3
		opsPerSec := runFor(benchDuration, func() {
			_ = tc.TBLS12381Keygen(2*f+1, nodeIDList(systemSize), randomness, curve)
		})
		fmt.Printf(" %13.2f", opsPerSec)
	}
	fmt.Println()

	fmt.Printf("         Sign ops/s:")
	for _, systemSize := range numShares {
		opsPerSec := runFor(benchDuration, func() {
			_, err := keys[systemSize][0].SignShare(msg)
			if err != nil {
				panic(err)
			}
		})
		fmt.Printf(" %13.2f", opsPerSec)
	}
	fmt.Println()

	fmt.Printf("  VerifyShare ops/s:")
	for _, systemSize := range numShares {
		opsPerSec := runFor(benchDuration, func() {
			err := keys[systemSize][0].VerifyShare(msg, shares[systemSize][0], 0)
			if err != nil {
				panic(err)
			}
		})
		fmt.Printf(" %13.2f", opsPerSec)
	}
	fmt.Println()

	fmt.Printf("  Reconstruct ops/s:")
	for _, systemSize := range numShares {
		f := (systemSize - 1) / 3
		opsPerSec := runFor(benchDuration, func() {
			_, err := keys[systemSize][0].Recover(msg, shares[systemSize][:2*f+1])
			if err != nil {
				panic(err)
			}
		})
		fmt.Printf(" %13.2f", opsPerSec)
	}
	fmt.Println()

	fmt.Printf("       Verify ops/s:")
	for _, systemSize := range numShares {
		opsPerSec := runFor(benchDuration, func() {
			err := keys[systemSize][0].VerifyFull(msg, sigs[systemSize])
			if err != nil {
				panic(err)
			}
		})
		fmt.Printf(" %13.2f", opsPerSec)
	}
	fmt.Println()

	return nil
}
