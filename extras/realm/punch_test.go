package realm

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPunchPacketEncodeDecode(t *testing.T) {
	meta := testPunchMetadata()

	for _, packetType := range []PunchPacketType{PunchPacketHello, PunchPacketAck} {
		t.Run(packetTypeName(packetType), func(t *testing.T) {
			packet, err := EncodePunchPacket(packetType, meta)
			require.NoError(t, err)
			assert.GreaterOrEqual(t, len(packet), punchMinWireLen)
			assert.LessOrEqual(t, len(packet), punchMaxWireLen)
			assert.False(t, bytes.Contains(packet, punchMagic[:]))

			decoded, err := DecodePunchPacket(packet, meta)
			require.NoError(t, err)
			assert.Equal(t, packetType, decoded.Type)
			assert.Equal(t, len(packet)-punchMinWireLen, decoded.PaddingLength)
		})
	}
}

func TestPunchPacketRejectsWrongMetadata(t *testing.T) {
	meta := testPunchMetadata()
	packet, err := EncodePunchPacket(PunchPacketHello, meta)
	require.NoError(t, err)

	_, err = DecodePunchPacket(packet, PunchMetadata{
		Nonce: "ffffffffffffffffffffffffffffffff",
		Obfs:  meta.Obfs,
	})
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrInvalidPunchPacket))

	_, err = DecodePunchPacket(packet, PunchMetadata{
		Nonce: meta.Nonce,
		Obfs:  "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
	})
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrInvalidPunchPacket))
}

func TestPunchPacketSaltVariesWireBytes(t *testing.T) {
	meta := testPunchMetadata()
	a, err := EncodePunchPacket(PunchPacketHello, meta)
	require.NoError(t, err)
	b, err := EncodePunchPacket(PunchPacketHello, meta)
	require.NoError(t, err)
	assert.NotEqual(t, a[:punchSaltLen], b[:punchSaltLen])
	assert.NotEqual(t, a, b)
}

func TestPunchPacketRejectsCorruptedPacket(t *testing.T) {
	meta := testPunchMetadata()
	packet, err := EncodePunchPacket(PunchPacketAck, meta)
	require.NoError(t, err)
	packet[0] ^= 0xff

	_, err = DecodePunchPacket(packet, meta)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrInvalidPunchPacket))
}

func TestPunchPacketRejectsBadLengths(t *testing.T) {
	meta := testPunchMetadata()

	_, err := DecodePunchPacket(make([]byte, punchMinWireLen-1), meta)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrInvalidPunchPacket))

	_, err = DecodePunchPacket(make([]byte, punchMaxWireLen+1), meta)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrInvalidPunchPacket))
}

func TestPunchPacketRejectsUnknownType(t *testing.T) {
	meta := testPunchMetadata()
	key, err := newPunchKey(meta)
	require.NoError(t, err)

	packet := make([]byte, punchMinWireLen)
	copy(packet[:punchSaltLen], []byte("12345678"))
	plain := packet[punchSaltLen:]
	copy(plain[:len(punchMagic)], punchMagic[:])
	plain[len(punchMagic)] = 0xff
	copy(plain[len(punchMagic)+1:punchHeaderLen], key.nonce[:])
	xorPunchPacket(plain, &key.obfs, packet[:punchSaltLen])

	_, err = DecodePunchPacket(packet, meta)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrInvalidPunchPacket))
}

func TestPunchPacketRejectsBadMetadata(t *testing.T) {
	_, err := EncodePunchPacket(PunchPacketHello, PunchMetadata{
		Nonce: "not-hex",
		Obfs:  testPunchMetadata().Obfs,
	})
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrInvalidPunchPacket))

	_, err = EncodePunchPacket(PunchPacketHello, PunchMetadata{
		Nonce: testPunchMetadata().Nonce,
		Obfs:  "not-hex",
	})
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrInvalidPunchPacket))
}

func TestPunchPacketPaddingVaries(t *testing.T) {
	meta := testPunchMetadata()
	seen := make(map[int]struct{})
	for range 64 {
		packet, err := EncodePunchPacket(PunchPacketHello, meta)
		require.NoError(t, err)
		decoded, err := DecodePunchPacket(packet, meta)
		require.NoError(t, err)
		assert.GreaterOrEqual(t, decoded.PaddingLength, 0)
		assert.LessOrEqual(t, decoded.PaddingLength, MaxPunchPadding)
		seen[decoded.PaddingLength] = struct{}{}
	}
	assert.Greater(t, len(seen), 1)
}

// TestPunchPacketWireFormatUnchanged checks packets against an independent
// implementation of the original format, so peers running older versions
// keep understanding each other.
func TestPunchPacketWireFormatUnchanged(t *testing.T) {
	meta := testPunchMetadata()
	nonce, _ := hex.DecodeString(meta.Nonce)
	obfsKey, _ := hex.DecodeString(meta.Obfs)
	legacyXOR := func(data, salt []byte) {
		h := sha256.New()
		h.Write(obfsKey)
		h.Write(salt)
		mask := h.Sum(nil)
		for i := range data {
			data[i] ^= mask[i%len(mask)]
		}
	}

	packet, err := EncodePunchPacket(PunchPacketAck, meta)
	require.NoError(t, err)
	plain := append([]byte(nil), packet[punchSaltLen:]...)
	legacyXOR(plain, packet[:punchSaltLen])
	assert.Equal(t, punchMagic[:], plain[:8])
	assert.Equal(t, byte(PunchPacketAck), plain[8])
	assert.Equal(t, nonce, plain[9:25])

	legacy := make([]byte, punchMinWireLen+40)
	copy(legacy, "saltsalt")
	copy(legacy[punchSaltLen:], punchMagic[:])
	legacy[punchSaltLen+8] = byte(PunchPacketHello)
	copy(legacy[punchSaltLen+9:], nonce)
	legacyXOR(legacy[punchSaltLen:], legacy[:punchSaltLen])
	decoded, err := DecodePunchPacket(legacy, meta)
	require.NoError(t, err)
	assert.Equal(t, PunchPacket{Type: PunchPacketHello, PaddingLength: 40}, decoded)
}

func testPunchMetadata() PunchMetadata {
	return PunchMetadata{
		Nonce: "00112233445566778899aabbccddeeff",
		Obfs:  "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
	}
}

func packetTypeName(packetType PunchPacketType) string {
	switch packetType {
	case PunchPacketHello:
		return "hello"
	case PunchPacketAck:
		return "ack"
	default:
		return "unknown"
	}
}
