package config

import (
	"os"

	"gopkg.in/yaml.v3"
)

type Config struct {
	FTPServersPath  string `yaml:"ftp_servers_path"`
	DataDirPath     string `yaml:"data_dir_path"`
	CertsDirPath    string `yaml:"certs_dir_path"`
	MaxChunkSize    int    `yaml:"max_chunk_size"`
	UploadQueueSize int    `yaml:"upload_queue_size"`
	UploadWorkers   int    `yaml:"upload_workers"`
}

func LoadConfig(path string) (Config, error) {
	var config Config
	err := LoadConfigFromFile(path, &config)
	return config, err
}

func LoadConfigFromFile(path string, config *Config) error {
	content, err := LoadConfigFromFileContent(path)
	if err != nil {
		return err
	}
	return UnmarshalConfig(content, config)
}

func LoadConfigFromFileContent(path string) ([]byte, error) {
	content, err := LoadFileContent(path)
	if err != nil {
		return nil, err
	}
	return content, nil
}

func LoadFileContent(path string) ([]byte, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return content, nil
}

func UnmarshalConfig(content []byte, config *Config) error {
	err := yaml.Unmarshal(content, config)
	if err != nil {
		return err
	}
	return nil
}
