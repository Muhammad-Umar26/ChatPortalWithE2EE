package middleware

import (
	"cnftp/internals/orchestrator"
	"sync"

	"github.com/goftp/server"
)

type MiddlewareDriverFactory struct {
	BaseFactory  server.DriverFactory
	Orchestrator *orchestrator.Orchestrator
}

func (f *MiddlewareDriverFactory) NewDriver() (server.Driver, error) {
	baseDriver, err := f.BaseFactory.NewDriver()
	if err != nil {
		return nil, err
	}
	return &MiddlewareDriver{
		Driver:       baseDriver,
		Orchestrator: f.Orchestrator,
		sizeCache:    make(map[string]int64),
		cacheMutex:   sync.RWMutex{},
	}, nil
}
