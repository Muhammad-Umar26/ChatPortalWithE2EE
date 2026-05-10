package main

import (
	"cnftp/internals/auth"
	"cnftp/internals/config"
	ftp_servers "cnftp/internals/ftp-servers"
	"cnftp/internals/middleware"
	"cnftp/internals/orchestrator"
	"log"
	"path"

	filedriver "github.com/goftp/file-driver"
	"github.com/goftp/server"
)

func main() {
	cfg, err := config.LoadConfig("./config.yml")
	if err != nil {
		log.Fatal(err)
	}

	auth := &auth.SimpleAuth{
		Username: "admin",
		Password: "admin",
	}

	baseDriverFactory := &filedriver.FileDriverFactory{
		RootPath: cfg.DataDirPath,
		Perm:     server.NewSimplePerm("admin", "admin"),
	}

	ftpServers := ftp_servers.LoadServers(cfg.FTPServersPath)

	orchestratorCfg := orchestrator.OrchestratorConfig{
		ChunkSize:       cfg.MaxChunkSize,
		UploadQueueSize: cfg.UploadQueueSize,
		UploadWorkers:   cfg.UploadWorkers,
	}
	orchestrator := orchestrator.NewOrchestrator(ftpServers, orchestratorCfg)
	orchestrator.Start()

	wrappedFactory := &middleware.MiddlewareDriverFactory{
		BaseFactory:  baseDriverFactory,
		Orchestrator: orchestrator,
	}

	opts := &server.ServerOpts{
		Factory:      wrappedFactory,
		Port:         8080,
		Hostname:     "0.0.0.0",
		Auth:         auth,
		PassivePorts: "40000-40010",

		TLS:          true,
		KeyFile:      path.Join(cfg.CertsDirPath, "key.pem"),
		CertFile:     path.Join(cfg.CertsDirPath, "cert.pem"),
		ExplicitFTPS: true,
	}

	ftpServer := server.NewServer(opts)
	log.Printf("FTP Server listening on %d", ftpServer.Port)
	err = ftpServer.ListenAndServe()
	if err != nil {
		log.Fatal(err)
	}
}
