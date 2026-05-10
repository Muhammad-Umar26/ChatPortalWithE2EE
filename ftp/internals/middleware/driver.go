package middleware

import (
	"cnftp/internals/orchestrator"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path"
	"strings"
	"sync"
	"time"

	"github.com/goftp/server"
)

type MiddlewareDriver struct {
	server.Driver
	Orchestrator *orchestrator.Orchestrator
	sizeCache    map[string]int64
	cacheMutex   sync.RWMutex
}

type fileInfoWrapper struct {
	base server.FileInfo
	name string
	size *int64
}

func (f fileInfoWrapper) Name() string { return f.name }
func (f fileInfoWrapper) Size() int64 {
	if f.size != nil {
		return *f.size
	}
	return f.base.Size()
}
func (f fileInfoWrapper) Mode() os.FileMode  { return f.base.Mode() }
func (f fileInfoWrapper) ModTime() time.Time { return f.base.ModTime() }
func (f fileInfoWrapper) IsDir() bool        { return f.base.IsDir() }
func (f fileInfoWrapper) Sys() any           { return f.base.Sys() }
func (f fileInfoWrapper) Owner() string      { return f.base.Owner() }
func (f fileInfoWrapper) Group() string      { return f.base.Group() }

func (m *MiddlewareDriver) manifestSizeFromPath(manifestPath string) (*int64, error) {
	_, manifestReader, err := m.Driver.GetFile(manifestPath, 0)
	if err != nil {
		return nil, err
	}

	var manifest orchestrator.Manifest
	decodeErr := json.NewDecoder(manifestReader).Decode(&manifest)
	closeErr := manifestReader.Close()
	if decodeErr != nil {
		return nil, decodeErr
	}
	if closeErr != nil {
		return nil, closeErr
	}

	size := manifest.Size
	return &size, nil
}

func (m *MiddlewareDriver) PutFile(path string, data io.Reader, appendFile bool) (int64, error) {
	fmt.Printf("[MIDDLEWARE] Pre-Upload Hook: Target path is %s\n", path)

	if err := m.ensureDirectories(path); err != nil {
		return 0, err
	}

	fileID, bytesWritten, err := m.Orchestrator.PutFile(m.Driver, path, data)
	if err != nil {
		fmt.Printf("[MIDDLEWARE] Post-Upload Hook: Error occurred while uploading file: %v\n", err)
		return bytesWritten, err
	}

	m.cacheMutex.Lock()
	if m.sizeCache == nil {
		m.sizeCache = make(map[string]int64)
	}
	m.sizeCache[path] = bytesWritten
	m.cacheMutex.Unlock()

	fmt.Printf("[MIDDLEWARE] Post-Upload Hook: File ID: %s, Bytes written: %d, Error: %v\n", *fileID, bytesWritten, err)
	return bytesWritten, err
}

func (m *MiddlewareDriver) ensureDirectories(filePath string) error {
	dirPath := path.Clean(path.Dir(filePath))
	if dirPath == "." || dirPath == "/" {
		return nil
	}

	parts := strings.Split(strings.TrimPrefix(dirPath, "/"), "/")
	current := "/"
	for _, part := range parts {
		if part == "" {
			continue
		}
		if current == "/" {
			current = "/" + part
		} else {
			current = current + "/" + part
		}

		info, statErr := m.Driver.Stat(current)
		if statErr == nil {
			if info.IsDir() {
				continue
			}
			return fmt.Errorf("%s exists and is not a directory", current)
		}

		if mkErr := m.Driver.MakeDir(current); mkErr != nil {
			return mkErr
		}
	}

	return nil
}

func (m *MiddlewareDriver) GetFile(path string, offset int64) (int64, io.ReadCloser, error) {
	fmt.Printf("[MIDDLEWARE] Pre-Download Hook: Target path is %s\n", path)

	return m.Orchestrator.GetFile(m.Driver, path, offset)
}

func (m *MiddlewareDriver) ListDir(path string, callback func(server.FileInfo) error) error {
	fmt.Printf("[MIDDLEWARE] Pre-Listing Hook: Target path is %s\n", path)

	manifestSuffix := *m.Orchestrator.Config.ManifestSuffix

	return m.Driver.ListDir(path, func(info server.FileInfo) error {
		name := info.Name()
		if strings.HasSuffix(name, manifestSuffix) {
			displayName := strings.TrimSuffix(name, manifestSuffix)
			m.cacheMutex.RLock()
			cachedSize, ok := m.sizeCache[displayName]
			m.cacheMutex.RUnlock()
			if ok {
				size := cachedSize
				return callback(fileInfoWrapper{base: info, name: displayName, size: &size})
			}
			manifestPath := path + "/" + name
			manifestSize, err := m.manifestSizeFromPath(manifestPath)
			if err != nil {
				return callback(fileInfoWrapper{base: info, name: displayName})
			}
			m.cacheMutex.Lock()
			if m.sizeCache == nil {
				m.sizeCache = make(map[string]int64)
			}
			m.sizeCache[displayName] = *manifestSize
			m.cacheMutex.Unlock()
			return callback(fileInfoWrapper{base: info, name: displayName, size: manifestSize})
		}
		return callback(info)
	})
}

func (m *MiddlewareDriver) Stat(path string) (server.FileInfo, error) {
	fmt.Printf("[MIDDLEWARE] Pre-Stat Hook: Target path is %s\n", path)

	manifestSuffix := *m.Orchestrator.Config.ManifestSuffix

	info, err := m.Driver.Stat(path)
	if err == nil {
		if info.IsDir() {
			return info, nil
		}
		if strings.HasSuffix(info.Name(), manifestSuffix) {
			displayName := strings.TrimSuffix(info.Name(), manifestSuffix)
			m.cacheMutex.RLock()
			cachedSize, ok := m.sizeCache[displayName]
			m.cacheMutex.RUnlock()
			if ok {
				size := cachedSize
				return fileInfoWrapper{base: info, name: displayName, size: &size}, nil
			}
			manifestSize, sizeErr := m.manifestSizeFromPath(path)
			if sizeErr != nil {
				return fileInfoWrapper{base: info, name: displayName}, nil
			}
			m.cacheMutex.Lock()
			if m.sizeCache == nil {
				m.sizeCache = make(map[string]int64)
			}
			m.sizeCache[displayName] = *manifestSize
			m.cacheMutex.Unlock()
			return fileInfoWrapper{base: info, name: displayName, size: manifestSize}, nil
		}
		return info, nil
	}

	if strings.HasSuffix(path, manifestSuffix) {
		return nil, err
	}

	statPath := path + manifestSuffix
	info, err = m.Driver.Stat(statPath)
	if err != nil {
		return nil, err
	}
	if strings.HasSuffix(info.Name(), manifestSuffix) {
		displayName := strings.TrimSuffix(info.Name(), manifestSuffix)
		m.cacheMutex.RLock()
		cachedSize, ok := m.sizeCache[displayName]
		m.cacheMutex.RUnlock()
		if ok {
			size := cachedSize
			return fileInfoWrapper{base: info, name: displayName, size: &size}, nil
		}
		manifestSize, sizeErr := m.manifestSizeFromPath(statPath)
		if sizeErr != nil {
			return fileInfoWrapper{base: info, name: displayName}, nil
		}
		m.cacheMutex.Lock()
		if m.sizeCache == nil {
			m.sizeCache = make(map[string]int64)
		}
		m.sizeCache[displayName] = *manifestSize
		m.cacheMutex.Unlock()
		return fileInfoWrapper{base: info, name: displayName, size: manifestSize}, nil
	}
	return info, nil
}

func (m *MiddlewareDriver) DeleteFile(path string) error {
	fmt.Printf("[MIDDLEWARE] Pre-Delete Hook: Target path is %s\n", path)

	return m.Orchestrator.DeleteFile(m.Driver, path)
}

func (m *MiddlewareDriver) DeleteDir(path string) error {
	fmt.Printf("[MIDDLEWARE] Pre-DeleteDir Hook: Target path is %s\n", path)

	err := m.Orchestrator.DeleteDir(m.Driver, path)

	m.cacheMutex.Lock()
	if m.sizeCache != nil {
		prefix := path
		if !strings.HasSuffix(prefix, "/") {
			prefix += "/"
		}
		for key := range m.sizeCache {
			if key == path || strings.HasPrefix(key, prefix) {
				delete(m.sizeCache, key)
			}
		}
	}
	m.cacheMutex.Unlock()

	return err
}
