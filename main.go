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
	if configPath == "" {
		configPath = "/etc/mihomo/config.yaml"
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

	// ДОБАВЛЯЕМ СИСТЕМНЫЕ ГРУППЫ, которых нет в секции proxy-groups
	systemGroups := []string{"DIRECT", "REJECT", "PASS", "BLOCK"}
	for _, sg := range systemGroups {
		found := false
		for _, g := range groups {
			if g == sg {
				found = true
				break
			}
		}
		if !found {
			groups = append(groups, sg)
		}
	}

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
				// Обработка закомментированных правил в HeadComment
				if rNode.HeadComment != "" {
					lines := strings.Split(rNode.HeadComment, "\n")
					for _, line := range lines {
						cleanLine := strings.TrimSpace(line)
						if strings.HasPrefix(cleanLine, "#") {
							content := strings.TrimSpace(strings.TrimPrefix(cleanLine, "#"))
							// Если строка внутри комментария похожа на правило (начинается с типа или - )
							ruleRaw := strings.TrimPrefix(content, "- ")
							if isLikelyRule(ruleRaw) {
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

func isLikelyRule(s string) bool {
	// Простая проверка, является ли строка правилом Clash
	types := []string{"DOMAIN", "GEOSITE", "GEOIP", "IP-CIDR", "MATCH", "OR", "AND", "NOT", "RULE-SET"}
	for _, t := range types {
		if strings.HasPrefix(s, t) {
			return true
		}
	}
	return false
}

func parseSingleRule(raw string) Rule {
	trimmed := strings.TrimSpace(raw)
	parts := splitOutsideParentheses(trimmed)
	rule := Rule{Raw: raw}

	// Очищаем сегменты
	for i := range parts {
		parts[i] = strings.TrimSpace(parts[i])
	}

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
			// Кейс: GEOIP,private,DIRECT,no-resolve
			// Берем только первые три части, no-resolve откидываем
			rule.Type = parts[0]
			rule.Value = parts[1]
			rule.ProxyGroup = parts[2]
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
			result = append(result, current.String())
			current.Reset()
		} else {
			current.WriteRune(r)
		}
	}
	result = append(result, current.String())
	return result
}

func saveRules(c *gin.Context) {
	// Читаем тело запроса один раз
	bodyBytes, err := c.GetRawData()
	if err != nil {
		c.JSON(400, gin.H{"error": "Failed to read request"})
		return
	}

	var req struct {
		Rules       []Rule   `json:"rules"`
		ProxyGroups []string `json:"proxy_groups"`
	}

	// Пробуем новый формат
	if err := json.Unmarshal(bodyBytes, &req); err != nil || len(req.Rules) == 0 {
		// Если не вышло, пробуем старый формат (просто массив правил)
		var legacyRules []Rule
		if errLegacy := json.Unmarshal(bodyBytes, &legacyRules); errLegacy == nil {
			req.Rules = legacyRules
		} else {
			c.JSON(400, gin.H{"error": "Invalid JSON format"})
			return
		}
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
	if err := yaml.NewDecoder(fRead).Decode(&node); err != nil {
		fRead.Close()
		c.JSON(500, gin.H{"error": "YAML Read Error"})
		return
	}
	fRead.Close()

	if len(node.Content) == 0 {
		c.JSON(500, gin.H{"error": "Empty YAML"})
		return
	}

	root := node.Content[0]
	var rulesSeq *yaml.Node
	var proxyGroupsSeq *yaml.Node

	// Find existing sections
	for i := 0; i < len(root.Content); i += 2 {
		if root.Content[i].Value == "rules" {
			rulesSeq = root.Content[i+1]
		}
		if root.Content[i].Value == "proxy-groups" {
			proxyGroupsSeq = root.Content[i+1]
		}
	}

	// Update Proxy Groups if provided
	if len(req.ProxyGroups) > 0 {
		if proxyGroupsSeq == nil {
			// Create proxy-groups section if it doesn't exist
			keyNode := &yaml.Node{Kind: yaml.ScalarNode, Value: "proxy-groups"}
			proxyGroupsSeq = &yaml.Node{Kind: yaml.SequenceNode}
			root.Content = append(root.Content, keyNode, proxyGroupsSeq)
		}

		// Get existing group names
		existingGroups := make(map[string]bool)
		for _, g := range proxyGroupsSeq.Content {
			for j := 0; j < len(g.Content); j += 2 {
				if g.Content[j].Value == "name" {
					existingGroups[g.Content[j+1].Value] = true
				}
			}
		}

		systemGroups := map[string]bool{"DIRECT": true, "REJECT": true, "PASS": true, "BLOCK": true}

		// Add new groups
		for _, gName := range req.ProxyGroups {
			if !existingGroups[gName] && !systemGroups[gName] {
				newNode := &yaml.Node{
					Kind: yaml.MappingNode,
					Content: []*yaml.Node{
						{Kind: yaml.ScalarNode, Value: "name"},
						{Kind: yaml.ScalarNode, Value: gName},
						{Kind: yaml.ScalarNode, Value: "type"},
						{Kind: yaml.ScalarNode, Value: "select"},
						{Kind: yaml.ScalarNode, Value: "proxies"},
						{
							Kind: yaml.SequenceNode,
							Content: []*yaml.Node{
								{Kind: yaml.ScalarNode, Value: "DIRECT"},
							},
						},
					},
				}
				proxyGroupsSeq.Content = append(proxyGroupsSeq.Content, newNode)
				existingGroups[gName] = true
			}
		}
	}

	// Update Rules
	if rulesSeq != nil {
		rulesSeq.Content = nil
		for _, ur := range req.Rules {
			var line string
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
