package thresholdcrypto

import (
	"crypto/cipher"
	"crypto/sha256"
	"fmt"

	"github.com/drand/kyber"
	bls12381 "github.com/drand/kyber-bls12381"
	"github.com/drand/kyber/pairing"
	"github.com/drand/kyber/share"
	"github.com/drand/kyber/sign"
	"github.com/drand/kyber/sign/tbls"
	"golang.org/x/exp/slices"
)

type Curve int

const (
	G1 Curve = iota
	G2
)

// TBLSInst an instance of a BLS-based (t, len(members))-threshold signature scheme
// It is capable of creating signature shares with its (single) private key share,
// and validating/recovering signatures involving all group members.
type TBLSInst struct {
	t         int
	members   []int
	scheme    sign.ThresholdScheme
	sigGroup  kyber.Group
	privShare *share.PriShare
	public    *share.PubPoly
}

// Constructs a TBLS scheme using the BLS12-381 pairing, with signatures being points on the given curve (G1 or G2),
// and keys points on the other curve.
func tbls12381Scheme(curve Curve) (pairing.Suite, sign.ThresholdScheme, kyber.Group, kyber.Group) {
	suite := bls12381.NewBLS12381Suite()
	var scheme sign.ThresholdScheme
	var sigGroup, keyGroup kyber.Group

	if curve == G1 {
		scheme = tbls.NewThresholdSchemeOnG1(suite)
		sigGroup = suite.G1()
		keyGroup = suite.G2()
	} else {
		scheme = tbls.NewThresholdSchemeOnG2(suite)
		sigGroup = suite.G2()
		keyGroup = suite.G1()
	}

	return suite, scheme, sigGroup, keyGroup
}

// TBLS12381Keygen constructs a set TBLSInst for a given set of member nodes and threshold T
// with nByz byzantine nodes, using the BLS12-381 pairing, with signatures being points on curve G1,
// and keys points on curve G2.
func TBLS12381Keygen(T int, members []int, randSource cipher.Stream, curve Curve) []*TBLSInst {
	N := len(members)

	suite, scheme, sigGroup, keyGroup := tbls12381Scheme(curve)

	if randSource == nil {
		randSource = suite.RandomStream()
	}

	secret := sigGroup.Scalar().Pick(randSource)
	privFull := share.NewPriPoly(keyGroup, T, secret, randSource)
	public := privFull.Commit(keyGroup.Point().Base())

	privShares := privFull.Shares(N)
	instances := make([]*TBLSInst, N)
	for i := 0; i < N; i++ {
		instances[i] = &TBLSInst{
			sigGroup:  sigGroup,
			scheme:    scheme,
			privShare: privShares[i],
			public:    public,
			t:         T,
			members:   members,
		}
	}

	return instances
}

// SignShare constructs a signature share for the message.
func (inst *TBLSInst) SignShare(msg [][]byte) ([]byte, error) {
	return inst.scheme.Sign(inst.privShare, digest(msg))
}

// VerifyShare verifies that a signature share is for a given message from a given node.
func (inst *TBLSInst) VerifyShare(msg [][]byte, sigShare []byte, nodeID int) error {
	idx, err := tbls.SigShare(sigShare).Index()
	if err != nil {
		return err
	}

	if idx != slices.Index(inst.members, nodeID) {
		return fmt.Errorf("signature share belongs to another node")
	}

	return inst.scheme.VerifyPartial(inst.public, digest(msg), sigShare)
}

// VerifyFull verifies that a (full) signature is valid for a given message.
func (inst *TBLSInst) VerifyFull(msg [][]byte, sigFull []byte) error {
	return inst.scheme.VerifyRecovered(inst.public.Commit(), digest(msg), sigFull)
}

// Recover recovers a full signature from a set of (previously validated) shares, that are known to be from
// distinct nodes.
func (inst *TBLSInst) Recover(_ [][]byte, sigShares [][]byte) ([]byte, error) {
	// We don't use inst.scheme.Recover to avoid validating sigShares twice

	// This function is a modified version of the original implementation of inst.scheme.Recover
	// The original can be found at: https://github.com/drand/kyber/blob/9b6e107d216803c85237cd7c45196e5c545e447b/sign/tbls/tbls.go#L118

	pubShares := make([]*share.PubShare, 0, inst.t)
	for _, sig := range sigShares {
		sh := tbls.SigShare(sig)
		i, err := sh.Index()
		if err != nil {
			continue
		}
		point := inst.sigGroup.Point()
		if err := point.UnmarshalBinary(sh.Value()); err != nil {
			continue
		}
		pubShares = append(pubShares, &share.PubShare{I: i, V: point})
		if len(pubShares) >= inst.t {
			break
		}
	}

	if len(pubShares) < inst.t {
		return nil, fmt.Errorf("not enough valid partial signatures")
	}

	commit, err := share.RecoverCommit(inst.sigGroup, pubShares, inst.t, len(inst.members))
	if err != nil {
		return nil, err
	}

	sig, err := commit.MarshalBinary()
	if err != nil {
		return nil, err
	}

	return sig, nil
}

// digest computes the SHA256 of the concatenation of all byte slices in data.
func digest(data [][]byte) []byte {
	h := sha256.New()
	for _, d := range data {
		h.Write(d)
	}
	return h.Sum(nil)
}
