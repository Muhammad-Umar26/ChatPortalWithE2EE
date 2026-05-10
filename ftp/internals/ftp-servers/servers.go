package ftp_servers

import (
	"encoding/json"
	"os"

	"github.com/jlaffaye/ftp"
)

type Server struct {
	Name string `json:"name"`
	Host string `json:"host"`
	Port int    `json:"port"`
	User string `json:"username"`
	Pass string `json:"password"`
	Conn *ftp.ServerConn
}

func LoadServers(path string) []Server {
	content, err := os.ReadFile(path)
	if err != nil {
		panic(err)
	}

	var serversConfig struct {
		Servers []Server `json:"servers"`
	}
	err = json.Unmarshal(content, &serversConfig)
	if err != nil {
		panic(err)
	}

	return serversConfig.Servers
}
