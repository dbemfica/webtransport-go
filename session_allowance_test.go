package webtransport

import (
	"context"
	"testing"
	"time"

	"github.com/quic-go/quic-go/http3"
	"github.com/quic-go/quic-go/quicvarint"
	"github.com/stretchr/testify/require"
)

// TestSessionGrantsInitialAllowanceWhenFlowControlDisabled pins the allowance
// that clients built on Apple's Network.framework -- Safari 26 and any Cocoa
// WebKit build -- require before they consider a session's streams usable.
//
// Those clients do not act on the WT_INITIAL_MAX_* SETTINGS; they wait for the
// allowance to arrive on the CONNECT stream. Without it,
// WebTransport.createBidirectionalStream() never settles: the client waits for
// credit that is never sent, no application data is ever written, and the
// session is torn down by whatever application-level timeout the server
// applies. Chromium opens streams without waiting, which is why the omission
// goes unnoticed against it.
func TestSessionGrantsInitialAllowanceWhenFlowControlDisabled(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	clientConn, serverConn := newConnPair(t, newUDPConnLocalhost(t), newUDPConnLocalhost(t))

	clientStr, err := clientConn.OpenStreamSync(ctx)
	require.NoError(t, err)

	newSession(context.Background(), 42, clientConn, quicHTTP3Stream{clientStr}, "", sessionFlowControl{})

	serverStr, err := serverConn.AcceptStream(ctx)
	require.NoError(t, err)
	require.NoError(t, serverStr.SetReadDeadline(time.Now().Add(time.Second)))

	parser := http3.NewCapsuleParser(serverStr)

	// The order is the one the allowance is written in, and each capsule
	// travels in its own HTTP/3 DATA frame: the Network.framework client only
	// acts on the first capsule of a frame, so packing them together would
	// leave it blocked on the two it ignored.
	data, err := parseNextCapsule(parser)
	require.NoError(t, err)
	require.Equal(t, maxDataCapsule{MaximumData: uint64(quicvarint.Max)}, data)

	bidi, err := parseNextCapsule(parser)
	require.NoError(t, err)
	require.Equal(t, maxStreamsBidiCapsule{MaximumStreams: maxStreamsLimit}, bidi)

	uni, err := parseNextCapsule(parser)
	require.NoError(t, err)
	require.Equal(t, maxStreamsUniCapsule{MaximumStreams: maxStreamsLimit}, uni)
}

// TestSessionSendsNoAllowanceWhenFlowControlEnabled is the other half of the
// contract. With session flow control enabled the limits travel in the
// WT_INITIAL_MAX_* SETTINGS, and a capsule must strictly increase the peer's
// limit: restating what the SETTINGS already granted is a protocol violation
// the peer is entitled to reject.
func TestSessionSendsNoAllowanceWhenFlowControlEnabled(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	clientConn, serverConn := newConnPair(t, newUDPConnLocalhost(t), newUDPConnLocalhost(t))

	clientStr, err := clientConn.OpenStreamSync(ctx)
	require.NoError(t, err)

	sess := newSession(context.Background(), 42, clientConn, quicHTTP3Stream{clientStr}, "", sessionFlowControl{
		Enabled:               true,
		MaxIncomingStreams:    10,
		MaxIncomingUniStreams: 10,
		MaxIncomingData:       1 << 20,
	})
	// A capsule of its own, so the read below has something to find and the
	// test distinguishes "no allowance" from "nothing at all".
	sess.queueCapsule(streamsBlockedBidiCapsule{MaximumStreams: 42})

	serverStr, err := serverConn.AcceptStream(ctx)
	require.NoError(t, err)
	require.NoError(t, serverStr.SetReadDeadline(time.Now().Add(time.Second)))

	c, err := parseNextCapsule(http3.NewCapsuleParser(serverStr))
	require.NoError(t, err)
	require.Equal(t, streamsBlockedBidiCapsule{MaximumStreams: 42}, c)
}
