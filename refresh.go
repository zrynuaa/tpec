package tpec

import (
	"github.com/NebulousLabs/hdkey/eckey"
	"github.com/cloudflare/cfssl/scan/crypto/sha256"
	"github.com/zrynuaa/Go-secp256k1/secpk1"
	"log"
	"math/big"
)

type Party1RefreshCtx struct {
	// Input
	sk *Party1PrivateKey

	// Sign phase 1
	k1         *eckey.SecretKey
	R1         *eckey.PublicKey
	R1PoK      *DLogPoK
	R1PoKNonce Nonce

	// Sign phase 3
	R2 *eckey.PublicKey
}

func (sk1 *Party1PrivateKey) NewRefreshCtx() *Party1RefreshCtx {
	return &Party1RefreshCtx{
		sk: sk1,
	}
}

func (p *Party1RefreshCtx) Zero() {
	p.k1.Zero()
}

type Party2RefreshCtx struct {
	// Input
	sk *Party2PrivateKey

	// Sign phase 2
	R1PoKComm Comm
	k2        *eckey.SecretKey
	R2        *eckey.PublicKey
	R2PoK     *DLogPoK

	// Sign phase 4
	R1 *eckey.PublicKey
}

func (sk *Party2PrivateKey) NewRefreshCtx() *Party2RefreshCtx {
	return &Party2RefreshCtx{
		sk: sk,
	}
}

func (p *Party2RefreshCtx) Zero() {
	p.k2.Zero()
}

func (p *Party1) Refresh(p2 *Party2) (*Party1PrivateKey, error) {

	sk1 := &Party1PrivateKey{
		cfg:  p.cfg,
		PSK:  p.PSK,
		X1SK: p.x1,
		//PublicKey: p.,
	}
	p1Ctx := sk1.NewRefreshCtx()
	defer p1Ctx.Zero()

	sm1, err := p1Ctx.RefreshMsgPhase1(0)
	if err != nil {
		return nil, err
	}

	sk2, err := p2.PrivateKey()
	p2Ctx := sk2.NewRefreshCtx()
	defer p2Ctx.Zero()

	sm2, err := p2Ctx.RefreshMsgPhase2(0, sm1)
	if err != nil {
		return nil, err
	}

	sm3, R1, err := p1Ctx.RefreshMsgPhase3(0, sm2)
	if err != nil {
		return nil, err
	}

	R2, err := p2Ctx.RefreshMsgPhase4(0, sm3)
	if err != nil {
		return nil, err
	}

	if R1.String() == R2.String() {
		log.Println("OK")
	}

	newx1 := new(big.Int).SetBytes(p.x1[:])
	newx1.Mul(newx1, R1)
	newx1.Mod(newx1, p.cfg.Q3)

	newx2 := new(big.Int).SetBytes(p2.x2[:])
	newx2.Div(newx2, R2)
	newx2.Mod(newx1, p.cfg.Q3)

	x1, _ := eckey.NewSecretKeyInt(newx1)
	x2, _ := eckey.NewSecretKeyInt(newx1)

	return p.GenKey(p2, x1, x2)

	//return sk1, nil
}

type RefreshMsg1 struct {
	R1PoKComm Comm
}

func (p *Party1RefreshCtx) RefreshMsgPhase1(sid uint64) (*RefreshMsg1, error) {
	// TODO(conner): check sid

	k1, err := NewPrivKey(p.sk.cfg.Q)
	if err != nil {
		return nil, err
	}

	// TODO(conner): include sid?
	R1PoK, err := NewDLogPK(signPhase1Msg, k1)
	if err != nil {
		return nil, err
	}

	R1Comm, R1Nonce, err := Commit(R1PoK.Bytes())
	if err != nil {
		return nil, err
	}

	p.k1 = k1
	p.R1 = k1.PublicKey()
	p.R1PoK = R1PoK
	p.R1PoKNonce = R1Nonce

	return &RefreshMsg1{
		R1PoKComm: R1Comm,
	}, nil
}

type RefreshMsg2 struct {
	R2PoK *DLogPoK
}

func (p *Party2RefreshCtx) RefreshMsgPhase2(sid uint64, m1 *RefreshMsg1) (*RefreshMsg2, error) {
	// TODO check sid
	k2, err := NewPrivKey(p.sk.cfg.Q)
	if err != nil {
		return nil, err
	}

	R2PoK, err := NewDLogPK(signPhase2Msg, k2)
	if err != nil {
		return nil, err
	}

	p.R1PoKComm = m1.R1PoKComm
	p.k2 = k2
	p.R2 = k2.PublicKey()
	p.R2PoK = R2PoK

	return &RefreshMsg2{
		R2PoK: R2PoK,
	}, nil
}

type RefreshMsg3 struct {
	ckey       []byte
	R1PoK      *DLogPoK
	R1PoKNonce Nonce
}

func (p *Party1RefreshCtx) RefreshMsgPhase3(sid uint64, m2 *RefreshMsg2) (*RefreshMsg3,
	*big.Int, error) {
	err := m2.R2PoK.Verify(signPhase2Msg)
	if err != nil {
		return nil, nil, err
	}

	R2, err := m2.R2PoK.PK.Uncompress()
	if err != nil {
		return nil, nil, err
	}

	p.R2 = R2
	R2x, R2y := R2.Coords()
	Rx, Ry := secpk1.S256().ScalarMult(R2x, R2y, p.k1[:])
	Rsum := sha256.Sum256(append(Rx.Bytes(), Ry.Bytes()[:]...))
	var RInt big.Int
	RInt.SetBytes(Rsum[:])
	R := new(big.Int).Mod(&RInt, p.sk.cfg.Q3)
	//
	//var x1 big.Int
	//x1.SetBytes(p.sk.X1SK[:])
	//var newx1 big.Int
	//newx1.Mul(&x1, R)
	//newx1.Mod(&newx1, p.sk.cfg.Q3)
	//
	//p.sk.X1SK, _ = eckey.NewSecretKeyInt(&newx1)
	//
	//ckey, _, err := paillier.EncryptAndNonce(&p.sk.PSK.PublicKey, p.sk.X1SK[:])
	//if err != nil {
	//	return nil, err
	//}

	return &RefreshMsg3{
		//ckey:       ckey,
		R1PoK:      p.R1PoK,
		R1PoKNonce: p.R1PoKNonce,
	}, R, nil
}

func (p *Party2RefreshCtx) RefreshMsgPhase4(sid uint64, m3 *RefreshMsg3) (*big.Int, error) {
	err := p.R1PoKComm.Verify(m3.R1PoK.Bytes(), &m3.R1PoKNonce)
	if err != nil {
		return nil, err
	}

	err = m3.R1PoK.Verify(signPhase1Msg)
	if err != nil {
		return nil, err
	}

	R1, err := m3.R1PoK.PK.Uncompress()
	if err != nil {
		return nil, err
	}

	R1x, R1y := R1.Coords()
	Rx, Ry := secpk1.S256().ScalarMult(R1x, R1y, p.k2[:])
	Rsum := sha256.Sum256(append(Rx.Bytes(), Ry.Bytes()[:]...))
	var RInt big.Int
	RInt.SetBytes(Rsum[:])
	R := new(big.Int).Mod(&RInt, p.sk.cfg.Q3)
	return R, nil
}
