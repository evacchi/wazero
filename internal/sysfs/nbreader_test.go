package sysfs

import (
	"context"
	"strings"
	"testing"
	"time"
)

func Test_nbreader_Read(t *testing.T) {
	tests := []struct {
		name        string
		rd          *nbreader
		reqN, wantN int
		wantErr     bool
	}{
		{
			name:    "read",
			rd:      newNbreader(strings.NewReader("test reader")),
			reqN:    11,
			wantN:   11,
			wantErr: false,
		},
		{
			name:    "blocking reader",
			rd:      newNbreader(newBlockingReader(t)),
			reqN:    11,
			wantN:   0,
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			buf := make([]byte, tt.reqN)
			gotN, err := tt.rd.Read(buf)
			if (err != nil) != tt.wantErr {
				t.Errorf("Read() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if gotN != tt.wantN {
				t.Errorf("Read() gotN = %v, want %v", gotN, tt.wantN)
			}
		})
	}
}

func newBlockingReader(t *testing.T) blockingReader {
	timeout, cancelFunc := context.WithTimeout(context.Background(), 5*time.Second)
	t.Cleanup(cancelFunc)
	return blockingReader{ctx: timeout}
}

// blockingReader is an io.Reader that never terminates its read
// unless the embedded context is Done()
type blockingReader struct {
	ctx context.Context
}

// Read implements io.Reader
func (b blockingReader) Read(buf []byte) (n int, err error) {
	<-b.ctx.Done()
	return 0, nil
}
