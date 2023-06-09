package sysfs

import (
	"net"
	"testing"

	"github.com/tetratelabs/wazero/internal/testing/require"
)

func TestTcpConnFile_Write(t *testing.T) {
	listen, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer listen.Close()

	tcpAddr, err := net.ResolveTCPAddr("tcp", listen.Addr().String())
	require.NoError(t, err)
	tcp, err := net.DialTCP("tcp", nil, tcpAddr)
	require.NoError(t, err)
	defer tcp.Close() //nolint

	f, err := tcp.File()
	require.NoError(t, err)
	file := tcpConnFile{fd: f.Fd()}
	n, errno := file.Write([]byte("wazero"))
	require.Zero(t, errno)
	require.NotEqual(t, 0, n)

	conn, err := listen.Accept()
	require.NoError(t, err)
	defer conn.Close()

	bytes := make([]byte, 4)

	n, err = conn.Read(bytes)
	require.NoError(t, err)
	require.NotEqual(t, 0, n)

	require.Equal(t, "waze", string(bytes))
}

func TestTcpConnFile_Read(t *testing.T) {
	listen, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer listen.Close()

	tcpAddr, err := net.ResolveTCPAddr("tcp", listen.Addr().String())
	require.NoError(t, err)
	tcp, err := net.DialTCP("tcp", nil, tcpAddr)
	require.NoError(t, err)
	defer tcp.Close() //nolint

	n, err := tcp.Write([]byte("wazero"))
	require.NoError(t, err)
	require.NotEqual(t, 0, n)

	conn, err := listen.Accept()
	require.NoError(t, err)
	defer conn.Close()

	bytes := make([]byte, 4)

	f, err := conn.(*net.TCPConn).SyscallConn()
	require.NoError(t, err)
	err = f.Control(func(fd uintptr) {
		file := tcpConnFile{fd: fd}
		n, errno := file.Read(bytes)
		require.Zero(t, errno)
		require.NotEqual(t, 0, n)
	})
	require.NoError(t, err)
	require.Equal(t, "waze", string(bytes))
}

func TestTcpConnFile_Stat(t *testing.T) {
	listen, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer listen.Close()

	tcpAddr, err := net.ResolveTCPAddr("tcp", listen.Addr().String())
	require.NoError(t, err)
	tcp, err := net.DialTCP("tcp", nil, tcpAddr)
	require.NoError(t, err)
	defer tcp.Close() //nolint

	conn, err := listen.Accept()
	require.NoError(t, err)
	defer conn.Close()

	f, err := tcp.File()
	require.NoError(t, err)
	file := tcpConnFile{fd: f.Fd()}
	_, errno := file.Stat()
	require.Zero(t, errno, "Stat should not fail")
}
