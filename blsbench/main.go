package main

import (
	"os"
	"time"

	"github.com/spf13/cobra"
)

var (
	dataSize      int
	benchDuration time.Duration

	rootCmd = &cobra.Command{
		Use: "sigbench",
		Short: "Signature generation, verification, and aggregation benchmarking tool. " +
			"Measures the single-threaded performance of the kyber bls library.",
	}
)

func init() {
	rootCmd.PersistentFlags().IntVarP(&dataSize, "data-size", "d", 32, "Size of the signed data (in bytes).")
	rootCmd.PersistentFlags().DurationVarP(&benchDuration, "run-time", "t", 200*time.Millisecond, "Time duration of the benchmark for each operation.")
}

func main() {
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}

// ======================================================================
// Helper functions
// ======================================================================

// nodeIDList returns a slice of integers from 0 to n-1 to serve as node IDs.
func nodeIDList(n int) []int {
	idList := make([]int, n)
	for i := 0; i < n; i++ {
		idList[i] = i
	}
	return idList
}

// runFor repeatedly executes the given task for a given time duration d.
// When d elapses, runFor waits until the currently running instance of the task finishes (does not interrupt the task)
// and returns how many times (on average) per second the task was run.
func runFor(d time.Duration, task func()) float64 {
	startTime := time.Now()
	var i int
	for i = 0; time.Since(startTime) < d; i++ {
		task()
	}
	return float64(i) / time.Since(startTime).Seconds()
}
