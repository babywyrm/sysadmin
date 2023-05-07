//
// Golang SOCKS Proxy via JumpHost / MITM Server / Bastion Host
// https://gist.github.com/0187773933/1723b8f4be6910355d297949f5a5726e
//

package main

// socksie is a SOCKS4/5 compatible proxy that forwards connections via
// SSH to a remote host
// https://raw.githubusercontent.com/davecheney/socksie/master/socks.go

import (
	"fmt"
	"log"
	"net"
	"time"
	"io"
	"sync"
	"bytes"
	"context"
	"encoding/binary"
	"golang.org/x/crypto/ssh"
	robustly "github.com/VividCortex/robustly"
)

type Dialer interface {
	DialTCP( net string , laddr , raddr *net.TCPAddr ) ( net.Conn , error )
}

var connections = new( sync.WaitGroup )

func HandleSOCKS5Connection( local *net.TCPConn , dialer Dialer ) {
	connections.Add( 1 )
	defer local.Close()
	defer connections.Done()

	// SOCKS does not include a length in the header, so take
	// a punt that each request will be readable in one go.
	buf := make([]byte, 256)
	n, err := local.Read(buf)
	if err != nil || n < 2 {
		log.Printf("[%s] unable to read SOCKS header: %v", local.RemoteAddr(), err)
		return
	}
	buf = buf[:n]

	switch version := buf[0]; version {
	case 4:
		switch command := buf[1]; command {
		case 1:
			port := binary.BigEndian.Uint16(buf[2:4])
			ip := net.IP(buf[4:8])
			addr := &net.TCPAddr{IP: ip, Port: int(port)}
			buf := buf[8:]
			i := bytes.Index(buf, []byte{0})
			if i < 0 {
				log.Printf("[%s] unable to locate SOCKS4 user", local.RemoteAddr())
				return
			}
			user := buf[:i]
			log.Printf("[%s] incoming SOCKS4 TCP/IP stream connection, user=%q, raddr=%s", local.RemoteAddr(), user, addr)
			remote, err := dialer.DialTCP( "tcp4" , local.RemoteAddr().( *net.TCPAddr ) , addr )
			if err != nil {
				log.Printf("[%s] unable to connect to remote host: %v", local.RemoteAddr(), err)
				local.Write([]byte{0, 0x5b, 0, 0, 0, 0, 0, 0})
				return
			}
			local.Write([]byte{0, 0x5a, 0, 0, 0, 0, 0, 0})
			transfer(local, remote)
		default:
			log.Printf("[%s] unsupported command, closing connection", local.RemoteAddr())
		}
	case 5:
		authlen, buf := buf[1], buf[2:]
		auths, buf := buf[:authlen], buf[authlen:]
		if !bytes.Contains(auths, []byte{0}) {
			log.Printf("[%s] unsuported SOCKS5 authentication method", local.RemoteAddr())
			local.Write([]byte{0x05, 0xff})
			return
		}
		local.Write([]byte{0x05, 0x00})
		buf = make([]byte, 256)
		n, err := local.Read(buf)
		if err != nil {
			log.Printf("[%s] unable to read SOCKS header: %v", local.RemoteAddr(), err)
			return
		}
		buf = buf[:n]
		switch version := buf[0]; version {
		case 5:
			switch command := buf[1]; command {
			case 1:
				buf = buf[3:]
				switch addrtype := buf[0]; addrtype {
				case 1:
					if len(buf) < 8 {
						log.Printf("[%s] corrupt SOCKS5 TCP/IP stream connection request", local.RemoteAddr())
						local.Write([]byte{0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
						return
					}
					ip := net.IP(buf[1:5])
					port := binary.BigEndian.Uint16(buf[5:6])
					addr := &net.TCPAddr{IP: ip, Port: int(port)}
					log.Printf("[%s] incoming SOCKS5 TCP/IP stream connection, raddr=%s", local.RemoteAddr(), addr)
					remote, err := dialer.DialTCP("tcp", local.RemoteAddr().(*net.TCPAddr), addr)
					if err != nil {
						log.Printf("[%s] unable to connect to remote host: %v", local.RemoteAddr(), err)
						local.Write([]byte{0x05, 0x04, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
						return
					}
					local.Write([]byte{0x05, 0x00, 0x00, 0x01, ip[0], ip[1], ip[2], ip[3], byte(port >> 8), byte(port)})
					transfer(local, remote)
				case 3:
					addrlen, buf := buf[1], buf[2:]
					name, buf := buf[:addrlen], buf[addrlen:]
					ip, err := net.ResolveIPAddr("ip", string(name))
					if err != nil {
						log.Printf("[%s] unable to resolve IP address: %q, %v", local.RemoteAddr(), name, err)
						local.Write([]byte{0x05, 0x04, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
						return
					}
					port := binary.BigEndian.Uint16(buf[:2])
					addr := &net.TCPAddr{IP: ip.IP, Port: int(port)}
					remote, err := dialer.DialTCP("tcp", local.RemoteAddr().(*net.TCPAddr), addr)
					if err != nil {
						log.Printf("[%s] unable to connect to remote host: %v", local.RemoteAddr(), err)
						local.Write([]byte{0x05, 0x04, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
						return
					}
					local.Write([]byte{0x05, 0x00, 0x00, 0x01, addr.IP[0], addr.IP[1], addr.IP[2], addr.IP[3], byte(port >> 8), byte(port)})
					transfer(local, remote)

				default:
					log.Printf("[%s] unsupported SOCKS5 address type: %d", local.RemoteAddr(), addrtype)
					local.Write([]byte{0x05, 0x08, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
				}
			default:
				log.Printf("[%s] unknown SOCKS5 command: %d", local.RemoteAddr(), command)
				local.Write([]byte{0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
			}
		default:
			log.Printf("[%s] unnknown version after SOCKS5 handshake: %d", local.RemoteAddr(), version)
			local.Write([]byte{0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		}
	default:
		log.Printf("[%s] unknown SOCKS version: %d", local.RemoteAddr(), version)
	}
}

func transfer( in , out net.Conn ) {
	wg := new( sync.WaitGroup )
	wg.Add( 2 )
	f := func( in , out net.Conn , wg *sync.WaitGroup ) {
		n , err := io.Copy( out , in )
		log.Printf( "xfer done: in=%v\tout=%v\ttransfered=%d\terr=%v" , in.RemoteAddr() , out.RemoteAddr() , n , err )
		if conn , ok := in.( *net.TCPConn ); ok {
			conn.CloseWrite()
		}
		if conn , ok := out.( *net.TCPConn ); ok {
			conn.CloseRead()
		}
		wg.Done()
	}
	go f( in , out , wg )
	f( out , in , wg )
	wg.Wait()
	out.Close()
}

// newClientConn is a wrapper around ssh.NewClientConn
// https://github.com/gravitational/teleport/blob/5ad1a9025cdd9e5d5fad46a0d316128615efc29b/lib/client/client.go#L807
func new_client_connection( conn net.Conn , nodeAddress string , config *ssh.ClientConfig ) ( ssh.Conn , <-chan ssh.NewChannel , <-chan *ssh.Request , error ) {

	var ctx = context.Background()
	type response struct {
		conn   ssh.Conn
		chanCh <-chan ssh.NewChannel
		reqCh  <-chan *ssh.Request
		err    error
	}

	respCh := make( chan response , 1 )
	go func() {
		conn, chans, reqs, err := ssh.NewClientConn(conn, nodeAddress, config)
		respCh <- response{conn, chans, reqs, err}
	}()

	select {
		case resp := <-respCh:
			if resp.err != nil {
				return nil, nil, nil , nil
			}
			return resp.conn, resp.chanCh, resp.reqCh, nil
		case <-ctx.Done():
			errClose := conn.Close()
			if errClose != nil {
				fmt.Println( errClose )
			}
			// drain the channel
			<-respCh
			return nil, nil, nil , nil
	}
}

// Connect To 6105Pihole port that is being "autossh'd" into localhost of relaymain at port 10202
func ConnectToSecondary( jump_host_ssh_client *ssh.Client ) ( ssh_client *ssh.Client ) {
	SECONDARY_HOST_SSH_USER_NAME := "pi"
	SECONDARY_HOST_IP_ADDRESS := "127.0.0.1"
	SECONDARY_HOST_SSH_PORT := 10202
	var SECONDARY_SSH_KEY_FILE_DATA = []byte( `-----BEGIN OPENSSH PRIVATE KEY-----
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==
-----END OPENSSH PRIVATE KEY-----` )
	SECONDARY_SSH_KEY_FILE_PASSWORD := ""

	var auths []ssh.AuthMethod
	if SECONDARY_SSH_KEY_FILE_PASSWORD != "" {
		auths = append( auths , ssh.Password( SECONDARY_SSH_KEY_FILE_PASSWORD ) )
	}
	secondary_ssh_key_signer , secondary_ssh_key_signer_error := ssh.ParsePrivateKey( SECONDARY_SSH_KEY_FILE_DATA )
	if secondary_ssh_key_signer_error != nil {
		fmt.Printf( "unable to parse private key: %v\n" , secondary_ssh_key_signer_error )
	}
	auths = append( auths , ssh.PublicKeys( secondary_ssh_key_signer ) )

	ssh_config := &ssh.ClientConfig{
		User: SECONDARY_HOST_SSH_USER_NAME ,
		Auth: auths ,
		HostKeyCallback: func( hostname string , remote net.Addr , key ssh.PublicKey ) error {
			return nil
		} ,
		Timeout: 6 * time.Second ,
	}

	address_string := fmt.Sprintf( "%s:%d" , SECONDARY_HOST_IP_ADDRESS , SECONDARY_HOST_SSH_PORT )
	ssh_proxy_connection , ssh_proxy_connection_error := jump_host_ssh_client.Dial( "tcp" , address_string )
	//ssh_client , ssh_connection_error := jump_host_ssh_client.Dial( "tcp" , address_string , ssh_config )
	// ssh_client , ssh_connection_error := ssh.Dial( "tcp" , address_string , ssh_config )
	if ssh_proxy_connection_error != nil {
		log.Fatalf( "unable to connect to ssh proxy [%s]: %v" , address_string , ssh_proxy_connection_error )
	}
	//defer ssh_client.Close()

	conn , chans , _ , err := new_client_connection( ssh_proxy_connection , address_string , ssh_config )
	if err != nil {
		// if strings.Contains( trace.Unwrap( err ).Error() , "ssh: handshake failed" ) {
			ssh_proxy_connection.Close()
			return nil
		// }
		return nil
	}

	// We pass an empty channel which we close right away to ssh.NewClient
	// because the client need to handle requests itself.
	emptyCh := make( chan *ssh.Request )
	close( emptyCh )

	ssh_client = ssh.NewClient( conn , chans , emptyCh )

	return
}

// Connect To Relay Main at "111.222.333.444"
func ConnectToJumpHost() ( ssh_client *ssh.Client ) {
	JUMP_HOST_SSH_USER_NAME := "morphs"
	JUMP_HOST_IP_ADDRESS := "111.222.333.444"
	JUMP_HOST_SSH_PORT := 22
	var JUMP_HOST_SSH_KEY_FILE_DATA = []byte( `-----BEGIN OPENSSH PRIVATE KEY-----
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==
-----END OPENSSH PRIVATE KEY-----` )
	JUMP_HOST_SSH_KEY_FILE_PASSWORD := ""

	var auths []ssh.AuthMethod
	if JUMP_HOST_SSH_KEY_FILE_PASSWORD != "" {
		auths = append( auths , ssh.Password( JUMP_HOST_SSH_KEY_FILE_PASSWORD ) )
	}

	jump_host_signer , jump_host_signer_error := ssh.ParsePrivateKey( JUMP_HOST_SSH_KEY_FILE_DATA )
	if jump_host_signer_error != nil {
		fmt.Printf( "unable to parse jump host private key: %v\n" , jump_host_signer_error )
	}
	auths = append( auths , ssh.PublicKeys( jump_host_signer ) )

	ssh_config := &ssh.ClientConfig{
		User: JUMP_HOST_SSH_USER_NAME ,
		Auth: auths ,
		HostKeyCallback: func( hostname string , remote net.Addr , key ssh.PublicKey ) error {
			return nil
		} ,
		Timeout: 6 * time.Second ,
	}

	address_string := fmt.Sprintf( "%s:%d" , JUMP_HOST_IP_ADDRESS , JUMP_HOST_SSH_PORT )
	ssh_client , ssh_connection_error := ssh.Dial( "tcp" , address_string , ssh_config )
	if ssh_connection_error != nil {
		log.Fatalf( "unable to connect to [%s]: %v" , address_string , ssh_connection_error )
	}
	//defer ssh_client.Close()

	return
}

// Raspberry PI is using autossh systemd service to forward port 22 to 10202 on RelayMain
// Run() Connects to RelayMain JumpHost and then to Raspberry PI secondary on port 10202
// Then it Opens SOCKS Proxy on Port 10017 on localhost of machine running this
func Run() {
	jump_host_connection := ConnectToJumpHost()
	secondary_host_connection := ConnectToSecondary( jump_host_connection )
	fmt.Println( secondary_host_connection )

	SOCKS_HOST_IP := "127.0.0.1"
	SOCKS_PROXY_PORT := 10017

	socks_address_string := fmt.Sprintf( "%s:%d" , SOCKS_HOST_IP , SOCKS_PROXY_PORT )
	socks_listener , err := net.Listen( "tcp" , socks_address_string )
	if err != nil {
		log.Fatalf( "unable to listen on SOCKS port [%s]: %v" , socks_address_string , err )
	}
	defer socks_listener.Close()
	log.Printf( "listening for incoming SOCKS connections on [%s]\n" , socks_address_string )

	for {
		socks_connection , socks_connection_error := socks_listener.Accept()
		if socks_connection_error != nil {
			log.Fatalf( "failed to accept incoming SOCKS connection: %v" , socks_connection_error )
		}
		go HandleSOCKS5Connection( socks_connection.( *net.TCPConn ) , secondary_host_connection )
	}
	log.Println( "waiting for all existing connections to finish" )
	connections.Wait()
	log.Println( "shutting down" )
}


func RobustlyRun() {
	robustly.Run( Run , &robustly.RunOptions{
		RateLimit:  1.0,
		Timeout:    time.Second ,
		PrintStack: false ,
		RetryDelay: 0 * time.Nanosecond ,
	})
}

func main() {
	RobustlyRun()
}

//
//
