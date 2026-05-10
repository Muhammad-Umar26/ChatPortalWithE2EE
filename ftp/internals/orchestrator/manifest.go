package orchestrator

import (
	"bytes"
	ftp_servers "cnftp/internals/ftp-servers"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jlaffaye/ftp"
)

type Manifest struct {
	Name      string         `json:"name"`
	Size      int64          `json:"size"`
	ChunkSize int            `json:"chunkSize"`
	Chunks    []ManifestItem `json:"chunks"`
}

type ManifestItem struct {
	Path       string  `json:"path"`
	Size       int     `json:"size"`
	Offset     int64   `json:"offset"`
	Checksum   string  `json:"checksum"`
	ServerName *string `json:"server_name"`
	Data       []byte  `json:"-"`
}

type DistributeResult struct {
	ServerName string
	Error      error
	Item       ManifestItem
}

func (o *Orchestrator) createManifestChunk(buffer []byte, offset int64) ManifestItem {
	hashBytes := sha256.Sum256(buffer)
	checksum := hex.EncodeToString(hashBytes[:])

	fileId := uuid.New().String()

	return ManifestItem{
		Path:       fileId,
		Size:       len(buffer),
		Offset:     offset,
		Checksum:   checksum,
		Data:       buffer,
		ServerName: nil,
	}
}

func (o *Orchestrator) distributeManifest(ctx context.Context, manifest Manifest) <-chan DistributeResult {
	results := make(chan DistributeResult, len(manifest.Chunks))

	queues := make([]chan ManifestItem, len(o.Servers))
	var wg sync.WaitGroup
	for i := range o.Servers {
		queues[i] = make(chan ManifestItem)
		serverIndex := i
		wg.Add(1)
		go func(index int, q <-chan ManifestItem) {
			defer wg.Done()
			for item := range q {
				server := &o.Servers[index]
				err := o.storeChunk(index, server, item)
				if err == nil {
					item.ServerName = &server.Name
				}
				select {
				case results <- DistributeResult{ServerName: server.Name, Error: err, Item: item}:
				case <-ctx.Done():
					return
				}
			}
		}(serverIndex, queues[i])
	}

	// round robin send
	go func() {
		defer func() {
			for _, q := range queues {
				close(q)
			}
		}()

		for i, item := range manifest.Chunks {
			select {
			case queues[i%len(queues)] <- item:
			case <-ctx.Done():
				return
			}
		}
	}()

	go func() {
		wg.Wait()
		close(results)
	}()

	return results
}

func (o *Orchestrator) storeChunk(serverIndex int, server *ftp_servers.Server, item ManifestItem) error {
	const maxAttempts = 3
	var lastErr error
	for attempt := 0; attempt < maxAttempts; attempt++ {
		o.serverLocks[serverIndex].Lock()
		if server.Conn == nil {
			conn, err := o.connectServer(server)
			if err != nil {
				o.serverLocks[serverIndex].Unlock()
				lastErr = err
				time.Sleep(2 * time.Second)
				continue
			}
			server.Conn = conn
		}
		err := server.Conn.Stor(item.Path, bytes.NewReader(item.Data))
		o.serverLocks[serverIndex].Unlock()
		if err == nil {
			return nil
		}
		lastErr = err
		time.Sleep(2 * time.Second)
	}
	return lastErr
}

func (o *Orchestrator) connectServer(server *ftp_servers.Server) (*ftp.ServerConn, error) {
	addr := fmt.Sprintf("%s:%d", server.Host, server.Port)
	conn, err := ftp.Dial(addr, ftp.DialWithTimeout(5*time.Second))
	if err != nil {
		return nil, err
	}
	if err := conn.Login(server.User, server.Pass); err != nil {
		_ = conn.Quit()
		return nil, err
	}
	return conn, nil
}

func (o *Orchestrator) verifyManifestItem(data []byte, item ManifestItem) error {
	if len(data) != item.Size {
		return fmt.Errorf("chunk size mismatch for %s: got %d want %d", item.Path, len(data), item.Size)
	}
	hashBytes := sha256.Sum256(data)
	checksum := hex.EncodeToString(hashBytes[:])
	if checksum != item.Checksum {
		return fmt.Errorf("chunk checksum mismatch for %s", item.Path)
	}
	return nil
}

func (o *Orchestrator) manifestPathFor(name string) string {
	if strings.HasSuffix(name, *o.Config.ManifestSuffix) {
		return name
	}
	return name + *o.Config.ManifestSuffix
}
