package knox
//Payloads work by implementing the payload interface.
//Any valid payload can be passed to the various port listeners.

import "fmt"

type payload interface {
	Payload(Hostinfo)
}

type SimplePayload int

func (p SimplePayload) Payload(data Hostinfo) {
	fmt.Println("A payload was triggered by", data.IP)
}


