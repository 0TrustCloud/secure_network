package secure_network

import (
	"encoding/binary"
	"fmt"
	"io"
)

func WriteFrame(
	w io.Writer,
	payload []byte,
) error {

	size := uint32(len(payload))

	var hdr [4]byte

	binary.BigEndian.PutUint32(
		hdr[:],
		size,
	)

	if _, err := w.Write(hdr[:]); err != nil {
		return err
	}

	_, err := w.Write(payload)

	return err
}

func ReadFrame(
	r io.Reader,
	maxSize uint32,
) ([]byte, error) {

	var hdr [4]byte

	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, err
	}

	size := binary.BigEndian.Uint32(hdr[:])

	if size == 0 {
		return nil, fmt.Errorf("empty frame")
	}

	if size > maxSize {
		return nil, fmt.Errorf(
			"frame exceeds max size",
		)
	}

	buf := make([]byte, size)

	_, err := io.ReadFull(r, buf)

	return buf, err
}
