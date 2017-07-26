package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"log"
	"math/big"
	"os"
	"os/signal"
	"syscall"

	"bytes"

	"time"

	quic "github.com/lucas-clemente/quic-go"
)

const message = "foobar"

// We start a server echoing data on the first stream the client opens,
// then connect with a client, send the message, and wait for its receipt.
func main() {
	addr := flag.String("addr", ":5454", "set listen address")
	flag.Parse()

	go func() { log.Fatal(echoServer(*addr)) }()
	sigs := make(chan os.Signal, 1)
	done := make(chan bool, 1)

	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		sig := <-sigs
		fmt.Println()
		fmt.Println(sig)
		done <- true
	}()

	fmt.Println("awaiting signal")
	<-done
	fmt.Println("exiting")
}

// Start a server that echos all data on the first stream opened by the client
func echoServer(addr string) error {
	listener, err := quic.ListenAddr(addr, generateTLSConfig(), nil)
	if err != nil {
		return err
	}
	log.Println("start listen:", addr)

	for {
		sess, err := listener.Accept()
		if err != nil {
			log.Println("listener error ", err.Error())
			return err
		}
		log.Printf("accept new session %v\n", sess)
		go serveSession(sess)

	}
}

func serveSession(ss quic.Session) {
	for {
		stream, err := ss.AcceptStream()
		if err != nil {
			log.Println("Session error wubb ", err.Error())
			return
		}
		log.Printf("accept new stream %v\n", stream)
		// Echo through the loggingWriter
		go serveStream(stream)

	}
}

func serveStream(st quic.Stream) {
	cnt := 0
	stname := ""
	for {
		buf := make([]byte, 64)
		n, err := st.Read(buf)
		if err != nil {
			log.Println("stream read error ", err.Error())
			return
		}
		if stname == "" {
			stname = string(buf[:n])
		}
		log.Println("stream  read  :", stname, cnt, string(buf[:n]))
		time.Sleep(time.Second)
		echo := bytes.NewBufferString(fmt.Sprintf("echo %d at :", cnt))
		echo.WriteString(time.Now().String())
		log.Println("echo ", stname, cnt)
		_, err = st.Write(echo.Bytes())
		if err != nil {
			log.Println("stream write error ", err.Error())
			return
		}
		cnt++

	}
}

// Setup a bare-bones TLS config for the server
func generateTLSConfig() *tls.Config {
	key, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		panic(err)
	}
	template := x509.Certificate{SerialNumber: big.NewInt(1)}
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		panic(err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		panic(err)
	}
	return &tls.Config{Certificates: []tls.Certificate{tlsCert}}
}
