package filesystem

import "io"

func NewNop() *Nop {
	return &Nop{}
}

func (f *Nop) Open(name string) (io.ReadCloser, error) {
	return DiscardCloser{}, nil
}

func (f *Nop) Create(name string) (io.WriteCloser, error) {
	return DiscardCloser{}, nil
}

type DiscardCloser struct {
}

func (ds DiscardCloser) Write(p []byte) (n int, err error) {
	return 0, nil
}

func (ds DiscardCloser) Read(p []byte) (n int, err error) {
	return 0, nil
}

func (DiscardCloser) Close() error { return nil }

type Nop struct {
}
