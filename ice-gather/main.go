package main

import (
	"fmt"
	"log"
	"net"

	"github.com/ernado/ice"
)

func main() {
	log.SetFlags(log.Lshortfile)
	addrs, err := ice.DefaultGatherer.Gather()
	if err != nil {
		log.Fatal("failed to gather: ", err)
	}
	for _, a := range addrs {
		fmt.Printf("%s\n", a)
		if len(a.Zone) > 0 {
			fmt.Println("    skip")
			continue
		}
		laddr, err := net.ResolveUDPAddr("udp",
			a.ZeroPortAddr(),
		)
		if err != nil {
			log.Println("resolve: ", err)
			continue
		}
		c, err := net.ListenUDP("udp", laddr)
		if err != nil {
			fmt.Println("   ", "failed:", err)
			continue
		}
		fmt.Println("   ", "bind ok", c.LocalAddr())
		c.Close()
	}
}
