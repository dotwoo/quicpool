package quicpool

import (
	"crypto/tls"
	"errors"
	"time"

	quic "github.com/lucas-clemente/quic-go"
	"github.com/toolkits/container/nmap"
)

type QuicClientPool struct {
	SessionsMap *nmap.SafeMap
	ConnTW      time.Duration
	MaxConns    int
}

var (
	tlsConfig *tls.Config
	config    *quic.Config
	quicPool  *QuicClientPool
)

//InitQuicClientPool init pool
func InitQuicClientPool(tc *tls.Config, maxConns int, connTimeout time.Duration) *QuicClientPool {
	tlsConfig = tc
	config = &quic.Config{
		HandshakeTimeout: connTimeout,
		KeepAlive:        true,
	}
	quicPool = &QuicClientPool{
		SessionsMap: nmap.NewSafeMap(),
		ConnTW:      connTimeout,
		MaxConns:    maxConns,
	}
	return quicPool
}

//Get get quic stream by address
func (qp *QuicClientPool) Get(addr string) (quic.Stream, error) {
	var err error
	var st quic.Stream
	is, ok := qp.SessionsMap.Get(addr)
	if ok {
		s, ok := is.(quic.Session)
		if ok {
			st, err = s.OpenStreamSync()
			if err == nil {
				return st, nil
			}
			qp.SessionsMap.Remove(addr)
			s.Close(err)
		} else {
			qp.SessionsMap.Remove(addr)
		}
	}
	if qp.SessionsMap.Size() >= quicPool.MaxConns {
		return nil, errors.New("Conns number over pool size")
	}
	s, err := quic.DialAddr(addr, tlsConfig, config)
	if err != nil {
		return nil, err
	}
	qp.SessionsMap.Put(addr, s)
	st, err = s.OpenStreamSync()
	if err != nil {
		return nil, err
	}
	return st, nil
}

//Get get quic stream by address
func Get(addr string) (quic.Stream, error) {
	if quicPool == nil {
		return nil, errors.New("quic pool is nil")
	}
	return quicPool.Get(addr)
}
