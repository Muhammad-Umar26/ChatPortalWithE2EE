package orchestrator

import (
	"bytes"
	ftp_servers "cnftp/internals/ftp-servers"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"path"
	"strings"
	"sync"
	"time"

	"github.com/goftp/server"
	"github.com/jlaffaye/ftp"
)

type OrchestratorConfig struct {
	ChunkSize       int
	ManifestSuffix  *string
	UploadQueueSize int
	UploadWorkers   int
}

type Orchestrator struct {
	Servers           []ftp_servers.Server
	Config            OrchestratorConfig
	serverNameToIndex map[string]int
	serverLocks       []sync.Mutex
	uploadQueue       chan uploadTask
}

type uploadTask struct {
	manifest     Manifest
	manifestPath string
	driver       server.Driver
}

var defaultManifestSuffix = ".manifest.json"

func NewOrchestrator(servers []ftp_servers.Server, config OrchestratorConfig) *Orchestrator {
	serverNameToIndex := make(map[string]int)
	for i, server := range servers {
		serverNameToIndex[server.Name] = i
	}

	if config.ManifestSuffix == nil {
		config.ManifestSuffix = &defaultManifestSuffix
	}
	if config.UploadQueueSize <= 0 {
		config.UploadQueueSize = 32
	}
	if config.UploadWorkers <= 0 {
		config.UploadWorkers = 1
	}

	return &Orchestrator{
		Servers:           servers,
		Config:            config,
		serverNameToIndex: serverNameToIndex,
		serverLocks:       make([]sync.Mutex, len(servers)),
		uploadQueue:       make(chan uploadTask, config.UploadQueueSize),
	}
}

func (o *Orchestrator) Start() {
	for i := range o.Servers {
		addr := fmt.Sprintf("%s:%d", o.Servers[i].Host, o.Servers[i].Port)
		for {
			c, err := ftp.Dial(addr, ftp.DialWithTimeout(5*time.Second))
			if err != nil {
				fmt.Printf("[ORCHESTRATOR] Failed to connect to %s: %v\n", addr, err)
				time.Sleep(3 * time.Second)
				continue
			}
			loginErr := c.Login(o.Servers[i].User, o.Servers[i].Pass)
			if loginErr != nil {
				_ = c.Quit()
				fmt.Printf("[ORCHESTRATOR] Failed to login to %s: %v\n", addr, loginErr)
				time.Sleep(3 * time.Second)
				continue
			}
			o.Servers[i].Conn = c
			fmt.Println("Connected to", addr)
			break
		}
	}

	for i := 0; i < o.Config.UploadWorkers; i++ {
		go o.uploadWorker()
	}
}

func (o *Orchestrator) Stop() {
	for i := range o.Servers {
		if o.Servers[i].Conn != nil {
			o.Servers[i].Conn.Quit()
			fmt.Println("Disconnected from", o.Servers[i].Host)
		}
	}
}

func (o *Orchestrator) PutFile(driver server.Driver, path string, content io.Reader) (*string, int64, error) {
	offset := int64(0)

	manifestPath := o.manifestPathFor(path)
	if _, err := driver.Stat(manifestPath); err == nil {
		_ = o.DeleteFile(driver, manifestPath)
	}

	buf := make([]byte, o.Config.ChunkSize)
	chunks := make([]ManifestItem, 0)

	for {
		n, err := content.Read(buf)

		if n > 0 {
			chunkBytes := make([]byte, n)
			copy(chunkBytes, buf[:n])
			chunk := o.createManifestChunk(chunkBytes, offset)
			offset += int64(n)

			chunks = append(chunks, chunk)
		}

		if err == io.EOF {
			break
		}

		if err != nil {
			return nil, 0, err
		}
	}

	manifest := Manifest{
		Name:      path,
		Size:      offset,
		ChunkSize: o.Config.ChunkSize,
		Chunks:    chunks,
	}
	if manifest.Size == 0 {
		return nil, 0, fmt.Errorf("empty upload for %s", path)
	}

	manifestName := manifestPath
	manifestBytes, err := json.Marshal(manifest)
	if err != nil {
		return nil, 0, err
	}
	_, err = driver.PutFile(manifestName, bytes.NewReader(manifestBytes), false)
	if err != nil {
		return nil, 0, err
	}

	if err := o.enqueueUpload(manifest, manifestName, driver); err != nil {
		return nil, 0, err
	}

	return &path, offset, nil
}

func (o *Orchestrator) enqueueUpload(manifest Manifest, manifestPath string, driver server.Driver) error {
	select {
	case o.uploadQueue <- uploadTask{manifest: manifest, manifestPath: manifestPath, driver: driver}:
		return nil
	default:
		return fmt.Errorf("upload queue full")
	}
}

func (o *Orchestrator) uploadWorker() {
	for task := range o.uploadQueue {
		chunkIndexByPath := make(map[string]int, len(task.manifest.Chunks))
		for i, item := range task.manifest.Chunks {
			chunkIndexByPath[item.Path] = i
		}

		results := o.distributeManifest(context.Background(), task.manifest)
		for range task.manifest.Chunks {
			result := <-results
			if result.Item.ServerName != nil {
				if idx, ok := chunkIndexByPath[result.Item.Path]; ok {
					task.manifest.Chunks[idx].ServerName = result.Item.ServerName
				}
			}
			if result.Error != nil {
				fmt.Printf("[ORCHESTRATOR] Upload error for %s: %v\n", result.Item.Path, result.Error)
			}
		}

		manifestBytes, err := json.Marshal(task.manifest)
		if err != nil {
			fmt.Printf("[ORCHESTRATOR] Failed to marshal manifest %s: %v\n", task.manifestPath, err)
			continue
		}
		if _, err := task.driver.PutFile(task.manifestPath, bytes.NewReader(manifestBytes), false); err != nil {
			fmt.Printf("[ORCHESTRATOR] Failed to update manifest %s: %v\n", task.manifestPath, err)
		}
	}
}

func (o *Orchestrator) DeleteFile(driver server.Driver, manifestPath string) error {
	resolvedManifestPath := o.manifestPathFor(manifestPath)
	_, manifestReader, err := driver.GetFile(resolvedManifestPath, 0)
	if err != nil {
		return err
	}

	var manifest Manifest
	decodeErr := json.NewDecoder(manifestReader).Decode(&manifest)
	closeErr := manifestReader.Close()
	if decodeErr != nil {
		return decodeErr
	}
	if closeErr != nil {
		return closeErr
	}

	var deleteErrors []error
	for _, item := range manifest.Chunks {
		if item.ServerName == nil {
			deleteErrors = append(deleteErrors, fmt.Errorf("missing server name for %s", item.Path))
			continue
		}
		serverIndex, ok := o.serverNameToIndex[*item.ServerName]
		if !ok {
			deleteErrors = append(deleteErrors, fmt.Errorf("unknown server %s for %s", *item.ServerName, item.Path))
			continue
		}
		server := o.Servers[serverIndex]
		if server.Conn == nil {
			deleteErrors = append(deleteErrors, fmt.Errorf("server connection is nil for %s", server.Name))
			continue
		}
		o.serverLocks[serverIndex].Lock()
		err := server.Conn.Delete(item.Path)
		o.serverLocks[serverIndex].Unlock()
		if err != nil {
			deleteErrors = append(deleteErrors, err)
		}
	}

	manifestErr := driver.DeleteFile(resolvedManifestPath)
	if manifestErr != nil {
		deleteErrors = append(deleteErrors, manifestErr)
	}

	if len(deleteErrors) == 0 {
		return nil
	}

	return fmt.Errorf("delete completed with %d errors, first error: %w", len(deleteErrors), deleteErrors[0])
}

func (o *Orchestrator) DeleteDir(driver server.Driver, dirPath string) error {
	var entries []struct {
		name  string
		isDir bool
	}

	listErr := driver.ListDir(dirPath, func(info server.FileInfo) error {
		entries = append(entries, struct {
			name  string
			isDir bool
		}{
			name:  info.Name(),
			isDir: info.IsDir(),
		})
		return nil
	})
	if listErr != nil {
		return listErr
	}

	var deleteErrors []error
	manifestSuffix := ""
	if o.Config.ManifestSuffix != nil {
		manifestSuffix = *o.Config.ManifestSuffix
	}

	for _, entry := range entries {
		entryPath := path.Join(dirPath, entry.name)
		if entry.isDir {
			if err := o.DeleteDir(driver, entryPath); err != nil {
				deleteErrors = append(deleteErrors, err)
			}
			continue
		}

		if manifestSuffix != "" && strings.HasSuffix(entry.name, manifestSuffix) {
			if err := o.DeleteFile(driver, entryPath); err != nil {
				deleteErrors = append(deleteErrors, err)
			}
			continue
		}

		if err := driver.DeleteFile(entryPath); err != nil {
			deleteErrors = append(deleteErrors, err)
		}
	}

	if err := driver.DeleteDir(dirPath); err != nil {
		deleteErrors = append(deleteErrors, err)
	}

	if len(deleteErrors) == 0 {
		return nil
	}

	return fmt.Errorf("delete dir completed with %d errors, first error: %w", len(deleteErrors), deleteErrors[0])
}

func (o *Orchestrator) GetFile(driver server.Driver, manifestPath string, offset int64) (int64, io.ReadCloser, error) {
	resolvedManifestPath := o.manifestPathFor(manifestPath)
	_, manifestReader, err := driver.GetFile(resolvedManifestPath, 0)
	if err != nil {
		return 0, nil, err
	}

	var manifest Manifest
	decodeErr := json.NewDecoder(manifestReader).Decode(&manifest)
	closeErr := manifestReader.Close()
	if decodeErr != nil {
		return 0, nil, decodeErr
	}

	if closeErr != nil {
		return 0, nil, closeErr
	}

	responseSize := manifest.Size
	if offset >= responseSize {
		return 0, io.NopCloser(bytes.NewReader(nil)), nil
	}
	responseSize -= offset

	pipeReader, pipeWriter := io.Pipe()
	go func() {
		defer pipeWriter.Close()
		remainingSkip := offset
		for _, item := range manifest.Chunks {
			if item.ServerName == nil {
				pipeWriter.CloseWithError(fmt.Errorf("missing server name for %s", item.Path))
				return
			}
			serverIndex, ok := o.serverNameToIndex[*item.ServerName]
			if !ok {
				pipeWriter.CloseWithError(fmt.Errorf("unknown server %s for %s", *item.ServerName, item.Path))
				return
			}
			server := o.Servers[serverIndex]
			if server.Conn == nil {
				pipeWriter.CloseWithError(fmt.Errorf("server connection is nil for %s", server.Name))
				return
			}

			o.serverLocks[serverIndex].Lock()
			chunkReader, err := server.Conn.Retr(item.Path)
			o.serverLocks[serverIndex].Unlock()
			if err != nil {
				pipeWriter.CloseWithError(err)
				return
			}

			chunkBytes, readErr := io.ReadAll(chunkReader)
			closeErr := chunkReader.Close()
			if readErr != nil {
				pipeWriter.CloseWithError(readErr)
				return
			}

			if closeErr != nil {
				pipeWriter.CloseWithError(closeErr)
				return
			}

			if verifyErr := o.verifyManifestItem(chunkBytes, item); verifyErr != nil {
				pipeWriter.CloseWithError(verifyErr)
				return
			}

			if remainingSkip >= int64(len(chunkBytes)) {
				remainingSkip -= int64(len(chunkBytes))
				continue
			}

			if remainingSkip > 0 {
				chunkBytes = chunkBytes[remainingSkip:]
				remainingSkip = 0
			}

			_, writeErr := pipeWriter.Write(chunkBytes)
			if writeErr != nil {
				return
			}
		}
	}()

	return responseSize, pipeReader, nil
}
