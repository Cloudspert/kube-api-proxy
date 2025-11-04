package kubeApiProxy 

import (
  "net"
  "encoding/binary"
  "github.com/google/nftables"
)

type chainLocation struct {
     position  uint64
     chain     string
}

type nftRule struct {
     ruleType      string
     jumpChain     *nftables.Chain
     table         *nftables.Table
     chain         *nftables.Chain
     originalIP    []byte
     modifiedIP    []byte
     originalPort  []byte
     modifiedPort  []byte
     beforeChain   *nftables.Chain
}

type RuleSnapshot struct {
     Chain      *nftables.Chain
     Hashs      []string
}

func intToBytes(port uint) []byte {
	buf := make([]byte, 2)
	binary.BigEndian.PutUint16(buf, uint16(port))
	return buf
}

func IPToBytes(ip string) []byte {
	return net.ParseIP(ip).To4()
}
