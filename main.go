package main

import (
	"log"

	"wafbps/internal/ui"
)

func main() {
	if err := ui.Run(); err != nil {
		log.Fatal(err)
	}
}
