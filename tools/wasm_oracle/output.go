package main

import (
	"encoding/json"
	"io"
)

type statusLine struct {
	Operation  string `json:"operation"`
	Transcript string `json:"transcript"`
	Result     string `json:"result"`
	Category   string `json:"category,omitempty"`
}

func emitStatus(out io.Writer, line statusLine) {
	encoded, _ := json.Marshal(line)
	_, _ = out.Write(append(encoded, '\n'))
}
