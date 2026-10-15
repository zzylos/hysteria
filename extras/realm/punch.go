package realm

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
)

const (
	MaxPunchPadding = 1024

	punchSaltLen = 8
	// Plain punch payload before obfs:
	// 8-byte magic, 1-byte type, 16-byte nonce, then 0..1024 random padding bytes.
	punchHeaderLen  = 25
	punchMinWireLen = punchSaltLen + punchHeaderLen
	punchMaxWireLen = punchMinWireLen + MaxPunchPadding
)

var (
	ErrInvalidPunchPacket = errors.New("invalid punch packet")

	punchMagic = [8]byte{'H', 'Y', 'R', 'L', 'M', 'v', '1', 0}

	// Created once so that rejecting a packet doesn't allocate. Most
	// packets checked are not punch packets.
	errPunchTooShort = fmt.Errorf("%w: packet too short", ErrInvalidPunchPacket)
	errPunchTooLong  = fmt.Errorf("%w: packet too long", ErrInvalidPunchPacket)
	errPunchBadMagic = fmt.Errorf("%w: bad magic", ErrInvalidPunchPacket)
	errPunchBadType  = fmt.Errorf("%w: unknown packet type", ErrInvalidPunchPacket)
	errPunchBadNonce = fmt.Errorf("%w: nonce mismatch", ErrInvalidPunchPacket)
)

type PunchPacketType byte

const (
	PunchPacketHello PunchPacketType = 0x01
	PunchPacketAck   PunchPacketType = 0x02
)

type PunchPacket struct {
	Type          PunchPacketType
	PaddingLength int
}

// punchKey is PunchMetadata decoded from hex, so the hot paths don't
// decode it for every packet.
type punchKey struct {
	nonce [PunchNonceSize]byte
	obfs  [PunchObfsKeySize]byte
}

func newPunchKey(meta PunchMetadata) (punchKey, error) {
	nonce, obfsKey, err := decodePunchMetadata(meta)
	if err != nil {
		return punchKey{}, err
	}
	var k punchKey
	copy(k.nonce[:], nonce)
	copy(k.obfs[:], obfsKey)
	return k, nil
}

func EncodePunchPacket(packetType PunchPacketType, meta PunchMetadata) ([]byte, error) {
	if !validPunchPacketType(packetType) {
		return nil, errPunchBadType
	}
	key, err := newPunchKey(meta)
	if err != nil {
		return nil, err
	}
	return key.encode(packetType)
}

func (k *punchKey) encode(packetType PunchPacketType) ([]byte, error) {
	if !validPunchPacketType(packetType) {
		return nil, errPunchBadType
	}
	paddingLength, err := randomPaddingLength()
	if err != nil {
		return nil, err
	}
	packet := make([]byte, punchMinWireLen+paddingLength)
	if _, err := rand.Read(packet[:punchSaltLen]); err != nil {
		return nil, err
	}
	plain := packet[punchSaltLen:]
	copy(plain[:len(punchMagic)], punchMagic[:])
	plain[len(punchMagic)] = byte(packetType)
	copy(plain[len(punchMagic)+1:punchHeaderLen], k.nonce[:])
	if paddingLength > 0 {
		if _, err := rand.Read(plain[punchHeaderLen:]); err != nil {
			return nil, err
		}
	}
	xorPunchPacket(plain, &k.obfs, packet[:punchSaltLen])
	return packet, nil
}

func DecodePunchPacket(packet []byte, meta PunchMetadata) (PunchPacket, error) {
	if err := checkPunchPacketLen(packet); err != nil {
		return PunchPacket{}, err
	}
	key, err := newPunchKey(meta)
	if err != nil {
		return PunchPacket{}, err
	}
	return key.decode(packet)
}

// decode checks whether packet is a punch packet for this key. Only the
// fixed-size header is unmasked, into a stack buffer, so checking a packet
// that isn't one costs a single SHA-256 and no allocations.
func (k *punchKey) decode(packet []byte) (PunchPacket, error) {
	if err := checkPunchPacketLen(packet); err != nil {
		return PunchPacket{}, err
	}
	mask := punchMask(&k.obfs, packet[:punchSaltLen])
	var header [punchHeaderLen]byte
	for i := range header {
		header[i] = packet[punchSaltLen+i] ^ mask[i%len(mask)]
	}
	if !bytes.Equal(header[:len(punchMagic)], punchMagic[:]) {
		return PunchPacket{}, errPunchBadMagic
	}
	packetType := PunchPacketType(header[len(punchMagic)])
	if !validPunchPacketType(packetType) {
		return PunchPacket{}, errPunchBadType
	}
	if !bytes.Equal(header[len(punchMagic)+1:], k.nonce[:]) {
		return PunchPacket{}, errPunchBadNonce
	}
	return PunchPacket{
		Type:          packetType,
		PaddingLength: len(packet) - punchMinWireLen,
	}, nil
}

func checkPunchPacketLen(packet []byte) error {
	if len(packet) < punchMinWireLen {
		return errPunchTooShort
	}
	if len(packet) > punchMaxWireLen {
		return errPunchTooLong
	}
	return nil
}

func decodePunchMetadata(meta PunchMetadata) (nonce, obfsKey []byte, err error) {
	nonce, err = decodeHexSize("nonce", meta.Nonce, PunchNonceSize)
	if err != nil {
		return nil, nil, err
	}
	obfsKey, err = decodeHexSize("obfs", meta.Obfs, PunchObfsKeySize)
	if err != nil {
		return nil, nil, err
	}
	return nonce, obfsKey, nil
}

func decodeHexSize(name, value string, size int) ([]byte, error) {
	b, err := hex.DecodeString(value)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid %s", ErrInvalidPunchPacket, name)
	}
	if len(b) != size {
		return nil, fmt.Errorf("%w: invalid %s length", ErrInvalidPunchPacket, name)
	}
	return b, nil
}

func randomPaddingLength() (int, error) {
	n, err := rand.Int(rand.Reader, big.NewInt(MaxPunchPadding+1))
	if err != nil {
		return 0, err
	}
	return int(n.Int64()), nil
}

// punchMask returns SHA-256(obfsKey || salt), the XOR mask for a packet.
func punchMask(obfsKey *[PunchObfsKeySize]byte, salt []byte) [sha256.Size]byte {
	var buf [PunchObfsKeySize + punchSaltLen]byte
	copy(buf[:], obfsKey[:])
	copy(buf[PunchObfsKeySize:], salt)
	return sha256.Sum256(buf[:])
}

func xorPunchPacket(packet []byte, obfsKey *[PunchObfsKeySize]byte, salt []byte) {
	mask := punchMask(obfsKey, salt)
	for i := range packet {
		packet[i] ^= mask[i%len(mask)]
	}
}

func validPunchPacketType(packetType PunchPacketType) bool {
	return packetType == PunchPacketHello || packetType == PunchPacketAck
}
