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
	random "math/rand"
	"strings"
	"sync"
	"time"

	"github.com/dotwoo/quicpool"
	quic "github.com/lucas-clemente/quic-go"
)

// We start a server echoing data on the first stream the client opens,
// then connect with a client, send the message, and wait for its receipt.
func main() {
	addr := flag.String("srv", "localhost:5454", "set quic servers, split by ,")
	t := flag.Int("time", 10, "call times to each server")
	flag.Parse()
	quicpool.InitQuicClientPool(&tls.Config{InsecureSkipVerify: true}, 100, time.Minute)
	srvlist := strings.Split(*addr, ",")
	wg := new(sync.WaitGroup)
	for _, s := range srvlist {
		wg.Add(1)
		go func(addr string, times int) {
			clientMain(addr, times, wg)
			wg.Done()
		}(s, *t)
	}
	wg.Wait()
	log.Println("sleep")
	time.Sleep(time.Minute)
	log.Println("restart")
	for _, s := range srvlist {
		wg.Add(1)
		go func(addr string, times int) {
			clientMain(addr, times, wg)
			wg.Done()
		}(s, *t)
	}
	wg.Wait()
}

func clientMain(addr string, times int, wg *sync.WaitGroup) error {

	for i := 0; i < times; i++ {
		stream := quicpool.Get(addr)
		if stream == nil {
			log.Println("can get stream ", addr)
			return nil
		}
		wg.Add(1)
		go sendAndRead(i, stream, wg)
	}

	return nil
}

func sendAndRead(name int, st quic.Stream, wg *sync.WaitGroup) error {
	defer wg.Done()
	log.Printf("Client%d: \n", name)
	_, err := st.Write([]byte(fmt.Sprintf("client%d", name)))
	if err != nil {
		return err
	}

	buf := make([]byte, 128)
	_, err = st.Read(buf)
	if err != nil {
		return err
	}
	log.Printf("Client %d: Got '%s'\n", name, buf)
	r := random.New(random.NewSource(time.Now().UnixNano()))
	cnt := 2
	for i := 0; i < cnt; i++ {
		message := fmt.Sprintf("client%d,send no. %d message", name, i)
		log.Printf("Client %d: Sending '%s'\n", name, message)
		_, err = st.Write([]byte(message))
		if err != nil {
			return err
		}

		buf1 := make([]byte, 128)
		_, err = st.Read(buf1)
		if err != nil {
			return err
		}
		log.Printf("Client %d: Got '%s'\n", name, buf1)
		if i < cnt-1 {
			time.Sleep(time.Duration(r.Intn(10)) * time.Second)
		}
	}
	st.Close()
	return nil
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
