# bls-bench

This benchmark measures the performance of the
[kyber implementation of the BLS signature scheme](https://github.com/drand/kyber-bls12381).
Both threshold signatures and key/signature aggregation can be measured
using the respective commands `threshold` and `aggregate`.
All benchmarks are run sequentially on a single CPU core.

## Usage

Clone this repository, `cd` into its directory.
The basic version of the benchmark for, respectively, threshold signatures and signature aggregation
with default parameters can be run by executing
```shell
go run ./blsbench aggregate
```
and
```shell
go run ./blsbench threshold
```

A quick example of setting benchmarking parameters:

```shell
go run ./blsbench aggregate -d 1024 -t 500ms -n 10 -n 1000 
```
will use a random data array of 1024 bytes as the payload to be signed,
each operation will be evaluated for 500 milliseconds,
and the aggregation operations will be evaluated with 10 and 1000 signatures.

For the complete description of the commands and flags, run
```shell
go run ./blsbench -h
```

### Selecting the curve for signatures

The `aggregate` command always runs benchmarks with signatures on curve G1 and on G2.
For the `threshold` command, the curve can be selected using the `-g` option.

## Thresholds for threshold signatures

Currently, the threshold is hard-coded to be the first lowest integer
strictly greater than two thirds of the total number of shares.
E.g., if the number of shares is set to any of 4, 5, and 6, the threshold will be 3.
This corresponds to a system of _n_ nodes, _f_ of which are potentially (Byzantine-)faulty, with _n >= 3f + 1_.
In such a system, a quorum of _2f + 1_ would correspond to the selected threshold for reconstructing the BLS signature.

## Inefficiency in verifying threshold signature shares

The VerifyShare operation is currently inefficient - it depends on the threshold selected for the used threshold scheme.
This is a property of the implementation and probably can be worked around by pre-computing a point on the curve
for each node only once (instead of each time its partial signature is verified)
and reusing it for subsequent verifications.