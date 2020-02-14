package server

import (
	"encoding/json"
	"io"
)

func JsonRequestDecode(r io.Reader, body interface{}) error {
	d := json.NewDecoder(r)
	return d.Decode(&body)
}
