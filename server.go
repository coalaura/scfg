package scfg

import (
	"net"
	"strconv"
	"time"
)

type Server struct {
	HostName       string
	User           string
	Port           string
	ProxyJump      string
	IdentityFile   string
	ForwardAgent   string
	ConnectTimeout string
}

func (s *Server) DefaultUser() string {
	if s.User != "" {
		return s.User
	}

	return "root"
}

func (s *Server) DefaultPort() string {
	if s.Port != "" {
		return s.Port
	}

	return "22"
}

func (s *Server) Addr() string {
	return net.JoinHostPort(s.HostName, s.DefaultPort())
}

func (s *Server) Timeout(fallback time.Duration) time.Duration {
	dur, err := time.ParseDuration(s.ConnectTimeout)
	if err == nil {
		return dur
	}

	num, err := strconv.ParseInt(s.ConnectTimeout, 10, 64)
	if err == nil {
		return time.Duration(num) * time.Second
	}

	return fallback
}
