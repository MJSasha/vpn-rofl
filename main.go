package main

import (
	"bytes"
	"embed"
	"encoding/json"
	"fmt"
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
	Raw        string `json:"raw"`
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
	configPath = os.Getenv("CONFIG_PATH")
	mihomoAPI  = os.Getenv("MIHOMO_API")
)

func main() {
	if sshPort == "" {
		sshPort = "22"
	}
	gin.SetMode(gin.ReleaseMode)
	r := gin.Default()

	r.GET("/api/config", getConfig)
	r.POST("/api/rules", saveRules)
	r.GET("/", func(c *gin.Context) {
		file, _ := f.ReadFile("index.html")
		c.Data(200, "text/html; charset=utf-8", file)
	})

	log.Printf("🚀 Приложение запущено на :8080")
	r.Run(":8080")
}

func getSSHClient() (*ssh.Client, error) {
	config := &ssh.ClientConfig{
		User:            sshUser,
		Auth:            []ssh.AuthMethod{ssh.Password(sshPass)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         10 * time.Second,
	}
	return ssh.Dial("tcp", fmt.Sprintf("%s:%s", sshHost, sshPort), config)
}

func getConfig(c *gin.Context) {
	client, err := getSSHClient()
	if err != nil {
		c.JSON(500, gin.H{"error": "SSH failed: " + err.Error()})
		return
	}
	defer client.Close()

	sftpClient, err := sftp.NewClient(client)
	if err != nil {
		c.JSON(500, gin.H{"error": "SFTP failed"})
		return
	}
	defer sftpClient.Close()

	file, err := sftpClient.Open(configPath)
	if err != nil {
		c.JSON(500, gin.H{"error": "File not found"})
		return
	}
	defer file.Close()

	var node yaml.Node
	if err := yaml.NewDecoder(file).Decode(&node); err != nil {
		c.JSON(500, gin.H{"error": "YAML Error"})
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
		keyNode := root.Content[i]
		valNode := root.Content[i+1]

		if keyNode.Value == "proxy-groups" {
			for _, g := range valNode.Content {
				for j := 0; j < len(g.Content); j += 2 {
					if g.Content[j].Value == "name" {
						groups = append(groups, g.Content[j+1].Value)
					}
				}
			}
		}

		if keyNode.Value == "rules" {
			for _, rNode := range valNode.Content {
				// Обработка комментариев перед правилом как закомментированных правил
				if rNode.HeadComment != "" {
					lines := strings.Split(rNode.HeadComment, "\n")
					for _, line := range lines {
						content := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(line), "#"))
						if strings.HasPrefix(content, "-") {
							ruleRaw := strings.TrimSpace(strings.TrimPrefix(content, "-"))
							if ruleRaw != "" {
								rule := parseSingleRule(ruleRaw)
								rule.ID = len(rules)
								rule.Enabled = false
								rules = append(rules, rule)
							}
						}
					}
				}

				if rNode.Value != "" {
					rule := parseSingleRule(rNode.Value)
					rule.ID = len(rules)
					rule.Enabled = true
					rules = append(rules, rule)
				}
			}
		}
	}
	return rules, groups
}

func parseSingleRule(raw string) Rule {
	trimmed := strings.TrimSpace(raw)
	parts := splitOutsideParentheses(trimmed)
	rule := Rule{Raw: raw}

	switch len(parts) {
	case 1:
		rule.Type = parts[0]
		rule.ProxyGroup = parts[0]
	case 2:
		rule.Type = parts[0]
		rule.ProxyGroup = parts[1]
	case 3:
		rule.Type = parts[0]
		rule.Value = parts[1]
		rule.ProxyGroup = parts[2]
	default:
		if len(parts) >= 4 {
			rule.Type = parts[0]
			rule.Value = parts[1]
			// Собираем группу и опции (например, DIRECT,no-resolve) вместе
			rule.ProxyGroup = strings.Join(parts[2:], ",")
		}
	}
	return rule
}

func splitOutsideParentheses(s string) []string {
	var result []string
	var current strings.Builder
	balance := 0
	for _, r := range s {
		if r == '(' {
			balance++
		} else if r == ')' {
			balance--
		}
		if r == ',' && balance == 0 {
			result = append(result, strings.TrimSpace(current.String()))
			current.Reset()
		} else {
			current.WriteRune(r)
		}
	}
	result = append(result, strings.TrimSpace(current.String()))
	return result
}

func saveRules(c *gin.Context) {
	var updatedRules []Rule
	if err := c.ShouldBindJSON(&updatedRules); err != nil {
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

	fRead, _ := sftpClient.Open(configPath)
	var node yaml.Node
	yaml.NewDecoder(fRead).Decode(&node)
	fRead.Close()

	root := node.Content[0]
	for i := 0; i < len(root.Content); i += 2 {
		if root.Content[i].Value == "rules" {
			rulesSeq := root.Content[i+1]
			rulesSeq.Content = nil
			for _, ur := range updatedRules {
				// Пересобираем строку правила
				line := ""
				if ur.Value != "" {
					line = fmt.Sprintf("%s,%s,%s", ur.Type, ur.Value, ur.ProxyGroup)
				} else if ur.Type != ur.ProxyGroup {
					line = fmt.Sprintf("%s,%s", ur.Type, ur.ProxyGroup)
				} else {
					line = ur.Type
				}

				newNode := &yaml.Node{Kind: yaml.ScalarNode}
				if ur.Enabled {
					newNode.Value = line
				} else {
					newNode.Value = ""
					newNode.HeadComment = "# " + line
				}
				rulesSeq.Content = append(rulesSeq.Content, newNode)
			}
		}
	}

	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	enc.Encode(&node)

	fWrite, _ := sftpClient.Create(configPath)
	fWrite.Write(buf.Bytes())
	fWrite.Close()

	go triggerMihomo()
	c.JSON(200, gin.H{"status": "ok"})
}

func triggerMihomo() {
	if mihomoAPI == "" {
		return
	}
	url := fmt.Sprintf("%s/configs?force=true", mihomoAPI)
	body := map[string]string{"path": configPath}
	jb, _ := json.Marshal(body)
	req, _ := http.NewRequest("PUT", url, bytes.NewBuffer(jb))
	req.Header.Set("Content-Type", "application/json")
	http.DefaultClient.Do(req)
}
