package knox
//Payloads work by implementing the payload interface.
//Any valid payload can be passed to the various port listeners.

import "fmt"

type payload interface {
	Payload(string)
}

type SimplePayload int

func (p SimplePayload) Payload(ip string) {
	fmt.Println("A payload was triggered by", ip)
}


