package kv

import (
	"crypto/rand"
	"fmt"
)

func shamirSplit(secret []byte, shares, threshold int) ([][]byte, error) {
	if len(secret) == 0 {
		return nil, fmt.Errorf("secret must not be empty lol")
	}
	if threshold < 2 || threshold > shares || shares > 255 {
		return nil, fmt.Errorf("invalid threshold/shares: threshold=%d shares=%d", threshold, shares)
	}

	result := make([][]byte, shares)
	for i := range result {
		result[i] = make([]byte, len(secret)+1)
		result[i][len(secret)] = byte(i + 1)
	}

	for i, b := range secret {
		poly, err := newPolynomial(b, uint8(threshold-1))
		if err != nil {
			return nil, err
		}
		for j := 0; j < shares; j++ {
			x := uint8(j + 1)
			result[j][i] = polyEval(poly, x)
		}
	}
	return result, nil
}

func shamirCombine(parts [][]byte) ([]byte, error) {
	if len(parts) < 2 {
		return nil, fmt.Errorf("need at least 2 parts")
	}
	secretLen := len(parts[0]) - 1
	for _, p := range parts {
		if len(p) != secretLen+1 {
			return nil, fmt.Errorf("all parts must have equal length")
		}
	}

	secret := make([]byte, secretLen)
	xs := make([]uint8, len(parts))
	for i, p := range parts {
		xs[i] = p[secretLen]
	}

	ys := make([]uint8, len(parts))
	for i := range secret {
		for j, p := range parts {
			ys[j] = p[i]
		}
		secret[i] = lagrangeInterpolate(0, xs, ys)
	}
	return secret, nil
}

func newPolynomial(intercept, degree uint8) ([]uint8, error) {
	coeffs := make([]uint8, degree+1)
	coeffs[0] = intercept
	if degree == 0 {
		return coeffs, nil
	}
	if _, err := rand.Read(coeffs[1:]); err != nil {
		return nil, err
	}
	for coeffs[degree] == 0 {
		if _, err := rand.Read(coeffs[degree : degree+1]); err != nil {
			return nil, err
		}
	}
	return coeffs, nil
}

func polyEval(coeffs []uint8, x uint8) uint8 {
	result := uint8(0)
	for i := len(coeffs) - 1; i >= 0; i-- {
		result = gfAdd(gfMul(result, x), coeffs[i])
	}
	return result
}

func lagrangeInterpolate(x uint8, xs, ys []uint8) uint8 {
	result := uint8(0)
	for i := range xs {
		num := uint8(1)
		den := uint8(1)
		for j := range xs {
			if i == j {
				continue
			}
			num = gfMul(num, gfAdd(x, xs[j]))
			den = gfMul(den, gfAdd(xs[i], xs[j]))
		}
		result = gfAdd(result, gfMul(gfMul(ys[i], num), gfInv(den)))
	}
	return result
}

func gfAdd(a, b uint8) uint8 { return a ^ b }

func gfMul(a, b uint8) uint8 {
	if a == 0 || b == 0 {
		return 0
	}
	return gfExp[(int(gfLog[a])+int(gfLog[b]))%255]
}

func gfInv(a uint8) uint8 {
	if a == 0 {
		return 0
	}
	return gfExp[255-int(gfLog[a])]
}

var gfExp, gfLog = buildGFTables()

func buildGFTables() ([512]uint8, [256]uint8) {
	var exp [512]uint8
	var log [256]uint8
	x := 1
	for i := 0; i < 255; i++ {
		exp[i] = uint8(x)
		log[x] = uint8(i)
		x <<= 1
		if x&0x100 != 0 {
			x ^= 0x11d
		}
	}
	for i := 255; i < 512; i++ {
		exp[i] = exp[i-255]
	}
	return exp, log
}
