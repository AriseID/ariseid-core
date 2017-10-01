// Copyright 2017 The AriseID Authors
// This file is part AriseID.
//
// AriseID free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// AriseID distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along withariseid-core. If not, see <http://www.gnu.org/licenses/>.

package main

import (
	"bytes"
	"fmt"
	"math/rand"
	"path/filepath"
	"strings"
	"text/template"

	"github.com/ariseid/ariseid-core/log"
)

// aidstatsDockerfile is the Dockerfile required to build an aidstats backend
// and associated monitoring site.
var aidstatsDockerfile = `
FROM mhart/alpine-node:latest

RUN \
  apk add --update git                                         && \
  git clone --depth=1 https://github.com/karalabe/aid-netstats && \
	apk del git && rm -rf /var/cache/apk/*                       && \
	\
  cd /aid-netstats && npm install && npm install -g grunt-cli && grunt

WORKDIR /aid-netstats
EXPOSE 3000

RUN echo 'module.exports = {trusted: [{{.Trusted}}], banned: [{{.Banned}}], reserved: ["yournode"]};' > lib/utils/config.js

CMD ["npm", "start"]
`

// aidstatsComposefile is the docker-compose.yml file required to deploy and
// maintain an aidstats monitoring site.
var aidstatsComposefile = `
version: '2'
services:
  aidstats:
    build: .
    image: {{.Network}}/aidstats{{if not .VHost}}
    ports:
      - "{{.Port}}:3000"{{end}}
    environment:
      - WS_SECRET={{.Secret}}{{if .VHost}}
      - VIRTUAL_HOST={{.VHost}}{{end}}{{if .Banned}}
      - BANNED={{.Banned}}{{end}}
    logging:
      driver: "json-file"
      options:
        max-size: "1m"
        max-file: "10"
    restart: always
`

// deployAidstats deploys a new aidstats container to a remote machine via SSH,
// docker and docker-compose. If an instance with the specified network name
// already exists there, it will be overwritten!
func deployAidstats(client *sshClient, network string, port int, secret string, vhost string, trusted []string, banned []string) ([]byte, error) {
	// Generate the content to upload to the server
	workdir := fmt.Sprintf("%d", rand.Int63())
	files := make(map[string][]byte)

	trustedLabels := make([]string, len(trusted))
	for i, address := range trusted {
		trustedLabels[i] = fmt.Sprintf("\"%s\"", address)
	}
	bannedLabels := make([]string, len(banned))
	for i, address := range banned {
		bannedLabels[i] = fmt.Sprintf("\"%s\"", address)
	}

	dockerfile := new(bytes.Buffer)
	template.Must(template.New("").Parse(aidstatsDockerfile)).Execute(dockerfile, map[string]interface{}{
		"Trusted": strings.Join(trustedLabels, ", "),
		"Banned":  strings.Join(bannedLabels, ", "),
	})
	files[filepath.Join(workdir, "Dockerfile")] = dockerfile.Bytes()

	composefile := new(bytes.Buffer)
	template.Must(template.New("").Parse(aidstatsComposefile)).Execute(composefile, map[string]interface{}{
		"Network": network,
		"Port":    port,
		"Secret":  secret,
		"VHost":   vhost,
		"Banned":  strings.Join(banned, ","),
	})
	files[filepath.Join(workdir, "docker-compose.yaml")] = composefile.Bytes()

	// Upload the deployment files to the remote server (and clean up afterwards)
	if out, err := client.Upload(files); err != nil {
		return out, err
	}
	defer client.Run("rm -rf " + workdir)

	// Build and deploy the aidstats service
	return nil, client.Stream(fmt.Sprintf("cd %s && docker-compose -p %s up -d --build", workdir, network))
}

// aidstatsInfos is returned from an aidstats status check to allow reporting
// various configuration parameters.
type aidstatsInfos struct {
	host   string
	port   int
	secret string
	config string
	banned []string
}

// String implements the stringer interface.
func (info *aidstatsInfos) String() string {
	return fmt.Sprintf("host=%s, port=%d, secret=%s, banned=%v", info.host, info.port, info.secret, info.banned)
}

// checkAidstats does a health-check against an aidstats server to verify whid
// it's running, and if yes, gathering a collection of useful infos about it.
func checkAidstats(client *sshClient, network string) (*aidstatsInfos, error) {
	// Inspect a possible aidstats container on the host
	infos, err := inspectContainer(client, fmt.Sprintf("%s_aidstats_1", network))
	if err != nil {
		return nil, err
	}
	if !infos.running {
		return nil, ErrServiceOffline
	}
	// Resolve the port from the host, or the reverse proxy
	port := infos.portmap["3000/tcp"]
	if port == 0 {
		if proxy, _ := checkNginx(client, network); proxy != nil {
			port = proxy.port
		}
	}
	if port == 0 {
		return nil, ErrNotExposed
	}
	// Resolve the host from the reverse-proxy and configure the connection string
	host := infos.envvars["VIRTUAL_HOST"]
	if host == "" {
		host = client.server
	}
	secret := infos.envvars["WS_SECRET"]
	config := fmt.Sprintf("%s@%s", secret, host)
	if port != 80 && port != 443 {
		config += fmt.Sprintf(":%d", port)
	}
	// Retrieve the IP blacklist
	banned := strings.Split(infos.envvars["BANNED"], ",")

	// Run a sanity check to see if the port is reachable
	if err = checkPort(host, port); err != nil {
		log.Warn("Aidstats service seems unreachable", "server", host, "port", port, "err", err)
	}
	// Container available, assemble and return the useful infos
	return &aidstatsInfos{
		host:   host,
		port:   port,
		secret: secret,
		config: config,
		banned: banned,
	}, nil
}
