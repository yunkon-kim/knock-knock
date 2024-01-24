package main

import (
	"fmt"
	"time"

	"github.com/yunkon-kim/knock-knock/pkg/netutil"
)

func main() {
	for i := 0; i < 30; i++ {
		fmt.Printf("Attempt #%d\n", i+1)
		start := time.Now()

		publicIP, err := netutil.InquireVMPublicIP()
		if err != nil {
			fmt.Println("Error:", err)
			continue
		}

		elapsed := time.Since(start)
		fmt.Printf("Public IP address acquired: %s, Elapsed Time: %s\n", publicIP, elapsed)
	}
}
