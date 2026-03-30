package main

import (
	"bytes"
	"embed"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
	"gopkg.in/yaml.v3"
)

//go:embed index.html
var f embed.FS

type Rule struct {
	ID         int    `json:"id"`
	Type       string `json:"type"`
	Value      string `json:"value"`
	ProxyGroup string `json:"proxy_group"`
	Enabled    bool   `json:"enabled"`
	Raw        string `json:"raw"` // Full string for complex rules
}

type ConfigResponse struct {
	Rules       []Rule   `json:"rules"`
	ProxyGroups []string `json:"proxy_groups"`
}

var (
	sshHost    = os.Getenv("SSH_HOST")
	sshPort    = os.Getenv("SSH_PORT")
	sshUser    = os.Getenv("SSH_USER")
	sshPass    = os.Getenv("SSH_PASS")
	configPath = os.Getenv("CONFIG_PATH") // e.g. /opt/etc/xkeen/config.yaml
	mihomoAPI  = os.Getenv("MIHOMO_API")  // e.g. http://192.168.1.1:9090
)

func main() {
	if sshPort == "" {
		sshPort = "22"
	}

	r := gin.Default()

	// API Endpoints
	r.GET("/api/config", getConfig)
	r.POST("/api/rules", saveRules)

	// Frontend
	r.GET("/", func(c *gin.Context) {
		file, err := f.ReadFile("index.html")
		if err != nil {
			c.String(500, "Internal Server Error: index.html not found")
			return
		}
		c.Data(200, "text/html; charset=utf-8", file)
	})

	log.Printf("Server started on :8080")
	r.Run(":8080")
}

func getSSHClient() (*ssh.Client, error) {
	config := &ssh.ClientConfig{
		User: sshUser,
		Auth: []ssh.AuthMethod{
			ssh.Password(sshPass),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         5 * time.Second,
	}
	return ssh.Dial("tcp", fmt.Sprintf("%s:%s", sshHost, sshPort), config)
}

func getConfig(c *gin.Context) {
	if sshHost == "" || sshUser == "" || sshPass == "" || configPath == "" {
		c.JSON(500, gin.H{"error": "Environment variables (SSH_HOST, SSH_USER, etc.) are not set in docker-compose.yml"})
		return
	}

	client, err := getSSHClient()
	if err != nil {
		log.Printf("SSH connection failed: %v", err)
		c.JSON(500, gin.H{"error": "SSH connection failed: " + err.Error()})
		return
	}
	defer client.Close()

	sftpClient, err := sftp.NewClient(client)
	if err != nil {
		c.JSON(500, gin.H{"error": "SFTP failed: " + err.Error()})
		return
	}
	defer sftpClient.Close()

	file, err := sftpClient.Open(configPath)
	if err != nil {
		c.JSON(500, gin.H{"error": "Could not open config: " + err.Error()})
		return
	}
	defer file.Close()

	var node yaml.Node
	decoder := yaml.NewDecoder(file)
	if err := decoder.Decode(&node); err != nil {
		c.JSON(500, gin.H{"error": "YAML parse failed: " + err.Error()})
		return
	}

	rules, groups := parseConfigNode(&node)
	c.JSON(200, ConfigResponse{Rules: rules, ProxyGroups: groups})
}

func parseConfigNode(node *yaml.Node) ([]Rule, []string) {
	var rules []Rule
	var groups []string

	if node.Kind != yaml.DocumentNode || len(node.Content) == 0 {
		return rules, groups
	}

	root := node.Content[0]
	for i := 0; i < len(root.Content); i += 2 {
		key := root.Content[i].Value
		val := root.Content[i+1]

		if key == "proxy-groups" {
			for _, g := range val.Content {
				for j := 0; j < len(g.Content); j += 2 {
					if g.Content[j].Value == "name" {
						groups = append(groups, g.Content[j+1].Value)
					}
				}
			}
		}

		if key == "rules" {
			for idx, rNode := range val.Content {
				raw := rNode.Value
				enabled := true
				if strings.HasPrefix(raw, "# ") {
					enabled = false
					raw = strings.TrimPrefix(raw, "# ")
				}

				parts := strings.Split(raw, ",")
				rule := Rule{
					ID:      idx,
					Enabled: enabled,
					Raw:     raw,
				}
				if len(parts) >= 3 {
					rule.Type = parts[0]
					rule.Value = parts[1]
					rule.ProxyGroup = parts[2]
				} else {
					rule.Type = "OTHER"
					rule.Value = raw
				}
				rules = append(rules, rule)
			}
		}
	}
	return rules, groups
}

func saveRules(c *gin.Context) {
	var newRules []Rule
	if err := c.ShouldBindJSON(&newRules); err != nil {
		c.JSON(400, gin.H{"error": "Invalid data"})
		return
	}

	client, err := getSSHClient()
	if err != nil {
		c.JSON(500, gin.H{"error": "SSH failed"})
		return
	}
	defer client.Close()

	sftpClient, err := sftp.NewClient(client)
	if err != nil {
		c.JSON(500, gin.H{"error": "SFTP failed"})
		return
	}
	defer sftpClient.Close()

	// 1. Read existing to preserve structure
	file, err := sftpClient.Open(configPath)
	if err != nil {
		c.JSON(500, gin.H{"error": "Could not open config for reading: " + err.Error()})
		return
	}
	var node yaml.Node
	err = yaml.NewDecoder(file).Decode(&node)
	file.Close()
	if err != nil {
		c.JSON(500, gin.H{"error": "Could not decode YAML: " + err.Error()})
		return
	}

	// 2. Update rules in node
	if node.Kind == yaml.DocumentNode && len(node.Content) > 0 {
		root := node.Content[0]
		for i := 0; i < len(root.Content); i += 2 {
			if root.Content[i].Value == "rules" {
				rulesSeq := root.Content[i+1]
				rulesSeq.Content = nil // Clear existing
				for _, nr := range newRules {
					val := nr.Raw
					if !nr.Enabled {
						val = "# " + val
					}
					rulesSeq.Content = append(rulesSeq.Content, &yaml.Node{
						Kind:  yaml.ScalarNode,
						Value: val,
					})
				}
			}
		}
	}

	// 3. Write back
	output, err := yaml.Marshal(&node)
	if err != nil {
		c.JSON(500, gin.H{"error": "Could not marshal YAML: " + err.Error()})
		return
	}
	fWrite, err := sftpClient.Create(configPath)
	if err != nil {
		c.JSON(500, gin.H{"error": "Could not create config for writing: " + err.Error()})
		return
	}
	fWrite.Write(output)
	fWrite.Close()

	// 4. Trigger Mihomo reload
	go triggerMihomo()

	c.JSON(200, gin.H{"status": "ok"})
}

func triggerMihomo() {
	url := fmt.Sprintf("%s/configs?force=true", mihomoAPI)
	body := map[string]string{"path": configPath}
	jsonBody, _ := json.Marshal(body)
	
	req, _ := http.NewRequest("PUT", url, bytes.NewBuffer(jsonBody))
	req.Header.Set("Content-Type", "application/json")
	
	resp, err := http.DefaultClient.Do(req)
	if err == nil {
		defer resp.Body.Close()
		io.ReadAll(resp.Body)
	}
}
