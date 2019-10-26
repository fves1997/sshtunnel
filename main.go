package main

import (
	"encoding/json"
	"golang.org/x/crypto/ssh"
	"io"
	"io/ioutil"
	"log"
	"net"
	"os"
	"os/signal"
	"strconv"
	"sync"
	"time"
)

type Config struct {
	Tunnel Tunnel   `json:"tunnel"`
	Target []Target `json:"target"`
}
type Tunnel struct {
	Host     string `json:"host"`
	Username string `json:"username"`
	Password string `json:"password"`
}
type Target struct {
	Host     string `json:"host"`
	BindPort int    `json:"bind_port"`
}

func init() {
	file, err := os.Create("sshtools.log")
	if err != nil {
		log.Printf("Create log file error: %s", err.Error())
	}
	log.SetOutput(io.MultiWriter(file, os.Stdout))
}

func main() {
	config := load("config.json")
	log.Printf("-----------------------------------------")
	log.Printf("[ SSH  ]: %s\n", config.Tunnel.Host)
	for _, target := range config.Target {
		log.Printf("[Target]: %s\n", target.Host)
	}
	log.Printf("-----------------------------------------")

	ch := make(chan os.Signal)
	signal.Notify(ch, os.Kill, os.Interrupt)

	go tunnelExchangeData(config)

	sign := <-ch
	log.Printf("Rcv sign: %s\n", sign)
}

func load(file string) *Config {
	config := &Config{}
	bytes, err := ioutil.ReadFile(file)
	if err != nil {
		log.Fatalf("load config fail,error: %s", err.Error())
	}
	err = json.Unmarshal(bytes, config)
	if err != nil {
		log.Fatalf("Unmarshal fail,error:%s", err.Error())
	}
	return config
}

var count = 0
var countLock = sync.Mutex{}

func Count() int {
	countLock.Lock()
	count++
	countLock.Unlock()
	return count
}

func tunnelExchangeData(config *Config) {
	tunnelClient := NewTunnelConnect(config.Tunnel)
	for _, target := range config.Target {
		listener := ListenLocalPort(target.BindPort)
		go func(target Target) {
			targetAddr, _ := net.ResolveTCPAddr("tcp", target.Host)
			for {
				conn, err := listener.AcceptTCP()
				if err != nil {
					log.Printf("Rcv err:%s\n", err.Error())
					continue
				}

				targetConn, err := tunnelClient.DialTCP("tcp", nil, targetAddr)
				if err != nil {
					log.Printf("Connect fail Tunnel[%s] ----> Target[%s]\n", tunnelClient.RemoteAddr().String(), target.Host)
					continue
				}
				//log.Printf("Connected Tunnel[%s] ----> Target[%s]\n", tunnelClient.RemoteAddr().String(), target.Host)
				log.Printf("Exchange Data:  Localhost[0.0.0.0:%d] ----> Tunnel[%s] ----> Target[%s] Count:%d\n", target.BindPort, config.Tunnel.Host, target.Host, Count())
				copyConn := func(writer, reader net.Conn) {
					_, err := io.Copy(writer, reader)
					if err != nil {
						log.Printf("io.Copy error: %s", err)
					}
				}
				go copyConn(conn, targetConn)
				go copyConn(targetConn, conn)
			}
		}(target)
	}
}

// Listen local port
func ListenLocalPort(port int) *net.TCPListener {
	addr, _ := net.ResolveTCPAddr("tcp", ":"+strconv.Itoa(port))
	listener, err := net.ListenTCP("tcp", addr)
	if err != nil {
		log.Fatalf("Listen local port error:%s\r\n", err.Error())
	}
	log.Printf("Listen: %s\n", listener.Addr().String())
	return listener
}

//  Create tunnel connect
func NewTunnelConnect(tunnel Tunnel) *ssh.Client {
	clientConfig := ssh.ClientConfig{
		Config: ssh.Config{
			Rand:           nil,
			RekeyThreshold: 0,
			KeyExchanges:   nil,
			Ciphers:        nil,
			MACs:           nil,
		},
		User: tunnel.Username,
		Auth: []ssh.AuthMethod{
			ssh.Password(tunnel.Password),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         5 * time.Second,
	}
	client, err := ssh.Dial("tcp", tunnel.Host, &clientConfig)
	if err != nil {
		log.Printf("Dial error: %s", err.Error())
		log.Println("sleep 1s and retry")
		time.Sleep(1 * time.Second)
		return NewTunnelConnect(tunnel)
	}
	log.Printf("Connected Localhost[%s] ----> Tunnel[%s]\n", client.LocalAddr().String(), tunnel.Host)
	return client
}
