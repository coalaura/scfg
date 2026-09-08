package scfg

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

const maxIncludeDepth = 16

type Config map[string]*Server

type Resolver struct {
	blocks    []hostBlock
	home      string
	localUser string
}

type hostBlock struct {
	patterns []string
	options  []configOption
}

type configOption struct {
	keyword string
	value   string
}

type configParser struct {
	resolver *Resolver
	active   int
	stack    map[string]struct{}
}

func (r *Resolver) Resolve(host string) *Server {
	server := &Server{}
	matchedIdentity := false
	identityDisabled := false

	for blockIndex := range r.blocks {
		block := &r.blocks[blockIndex]
		if !matchHostBlock(block.patterns, host) {
			continue
		}

		for optionIndex := range block.options {
			option := &block.options[optionIndex]

			switch option.keyword {
			case "hostname":
				if server.HostName == "" {
					server.HostName = option.value
				}
			case "user":
				if server.User == "" {
					server.User = option.value
				}
			case "port":
				if server.Port == "" {
					server.Port = option.value
				}
			case "identityfile":
				if strings.EqualFold(option.value, "none") {
					server.IdentityFiles = []string{}
					identityDisabled = true
				} else if !identityDisabled {
					server.IdentityFiles = append(server.IdentityFiles, option.value)
				}

				matchedIdentity = true
			case "identitiesonly":
				if server.IdentitiesOnly == "" {
					server.IdentitiesOnly = option.value
				}
			case "proxyjump":
				if server.ProxyJump == "" {
					server.ProxyJump = option.value
				}
			case "forwardagent":
				if server.ForwardAgent == "" {
					server.ForwardAgent = option.value
				}
			case "connecttimeout":
				if server.ConnectTimeout == "" {
					server.ConnectTimeout = option.value
				}
			}
		}
	}

	if server.HostName == "" {
		server.HostName = host
	}

	if server.User == "" {
		server.User = r.localUser
	}

	if server.Port == "" {
		server.Port = "22"
	}

	if !matchedIdentity {
		server.IdentityFiles = defaultIdentityFiles()
	}

	if len(server.IdentityFiles) > 0 {
		server.IdentityFile = server.IdentityFiles[0]
	}

	return server
}

func ParseConfig(home string) (Config, error) {
	resolver, err := ParseResolver(home)
	if err != nil {
		return nil, err
	}

	config := make(Config)

	for blockIndex := range resolver.blocks {
		patterns := resolver.blocks[blockIndex].patterns

		for _, pattern := range patterns {
			if !literalHostPattern(pattern) {
				continue
			}

			if _, exists := config[pattern]; exists {
				continue
			}

			config[pattern] = resolver.Resolve(pattern)
		}
	}

	return config, nil
}

func ParseResolver(home string) (*Resolver, error) {
	current, err := user.Current()
	if err != nil {
		return nil, fmt.Errorf("determine local user: %w", err)
	}

	resolver := &Resolver{
		blocks:    []hostBlock{{}},
		home:      home,
		localUser: current.Username,
	}
	parser := configParser{
		resolver: resolver,
		stack:    make(map[string]struct{}),
	}
	path := filepath.Join(home, ".ssh", "config")

	err = parser.parseFile(path, 0, true)
	if err != nil {
		return nil, err
	}

	return resolver, nil
}

func (p *configParser) parseFile(path string, depth int, root bool) error {
	if depth > maxIncludeDepth {
		return fmt.Errorf("include depth exceeds %d at %q", maxIncludeDepth, path)
	}

	canonical, err := filepath.Abs(path)
	if err != nil {
		return fmt.Errorf("resolve config path %q: %w", path, err)
	}

	canonical = filepath.Clean(canonical)
	if _, exists := p.stack[canonical]; exists {
		return fmt.Errorf("include cycle at %q", canonical)
	}

	file, err := os.Open(canonical)
	if err != nil {
		if root && errors.Is(err, os.ErrNotExist) {
			return nil
		}

		return fmt.Errorf("open config %q: %w", canonical, err)
	}

	defer file.Close()

	p.stack[canonical] = struct{}{}
	defer delete(p.stack, canonical)

	scanner := bufio.NewScanner(file)
	lineNumber := 0

	for scanner.Scan() {
		lineNumber++

		words, parseErr := parseWords(scanner.Text())
		if parseErr != nil {
			return fmt.Errorf("%s:%d: %w", canonical, lineNumber, parseErr)
		}

		if len(words) == 0 {
			continue
		}

		parseErr = p.parseDirective(canonical, lineNumber, words, depth)
		if parseErr != nil {
			return parseErr
		}
	}

	err = scanner.Err()
	if err != nil {
		return fmt.Errorf("read config %q: %w", canonical, err)
	}

	return nil
}

func (p *configParser) parseDirective(path string, line int, words []string, depth int) error {
	keyword := strings.ToLower(words[0])
	values := words[1:]

	switch keyword {
	case "host":
		if len(values) == 0 {
			return fmt.Errorf("%s:%d: Host requires a pattern", path, line)
		}

		p.resolver.blocks = append(p.resolver.blocks, hostBlock{patterns: values})
		p.active = len(p.resolver.blocks) - 1

		return nil
	case "match":
		p.active = -1

		return nil
	}

	if p.active < 0 {
		return nil
	}

	switch keyword {
	case "include":
		if len(values) == 0 {
			return fmt.Errorf("%s:%d: Include requires a path", path, line)
		}

		return p.parseIncludes(values, depth+1)
	}

	if !supportedOption(keyword) {
		return nil
	}

	if len(values) != 1 {
		return fmt.Errorf("%s:%d: %s requires one value", path, line, words[0])
	}

	value := values[0]

	err := validateOption(keyword, value)
	if err != nil {
		return fmt.Errorf("%s:%d: %w", path, line, err)
	}

	block := &p.resolver.blocks[p.active]
	block.options = append(block.options, configOption{keyword: keyword, value: value})

	return nil
}

func (p *configParser) parseIncludes(patterns []string, depth int) error {
	base := filepath.Join(p.resolver.home, ".ssh")

	for _, pattern := range patterns {
		pattern = expandPath(p.resolver.home, pattern)
		if !filepath.IsAbs(pattern) {
			pattern = filepath.Join(base, pattern)
		}

		matches, err := filepath.Glob(pattern)
		if err != nil {
			return fmt.Errorf("invalid Include pattern %q: %w", pattern, err)
		}

		sort.Strings(matches)

		for _, match := range matches {
			err = p.parseFile(match, depth, false)
			if err != nil {
				return err
			}
		}
	}

	return nil
}

func supportedOption(keyword string) bool {
	switch keyword {
	case "hostname", "user", "port", "identityfile", "identitiesonly", "proxyjump", "forwardagent", "connecttimeout":
		return true
	default:
		return false
	}
}

func validateOption(keyword, value string) error {
	if value == "" {
		return fmt.Errorf("%s requires a non-empty value", keyword)
	}

	switch keyword {
	case "port":
		port, err := strconv.ParseUint(value, 10, 16)
		if err != nil || port == 0 {
			return fmt.Errorf("invalid Port %q", value)
		}
	case "connecttimeout":
		timeout, err := strconv.ParseUint(value, 10, 31)
		if err != nil {
			return fmt.Errorf("invalid ConnectTimeout %q", value)
		}

		_ = timeout
	case "identitiesonly", "forwardagent":
		if !yesNoValue(value) {
			return fmt.Errorf("invalid %s value %q", keyword, value)
		}
	}

	return nil
}

func yesNoValue(value string) bool {
	return strings.EqualFold(value, "yes") || strings.EqualFold(value, "no")
}

func matchHostBlock(patterns []string, host string) bool {
	if len(patterns) == 0 {
		return true
	}

	matched := false

	for _, pattern := range patterns {
		negated := strings.HasPrefix(pattern, "!")
		if negated {
			pattern = pattern[1:]
		}

		if pattern == "" || !matchHostPattern(pattern, host) {
			continue
		}

		if negated {
			return false
		}

		matched = true
	}

	return matched
}

func matchHostPattern(pattern, host string) bool {
	pattern = strings.ToLower(pattern)
	host = strings.ToLower(host)

	patternIndex := 0
	hostIndex := 0
	starIndex := -1
	retryIndex := 0

	for hostIndex < len(host) {
		if patternIndex < len(pattern) && (pattern[patternIndex] == '?' || pattern[patternIndex] == host[hostIndex]) {
			patternIndex++
			hostIndex++

			continue
		}

		if patternIndex < len(pattern) && pattern[patternIndex] == '*' {
			starIndex = patternIndex
			patternIndex++
			retryIndex = hostIndex

			continue
		}

		if starIndex == -1 {
			return false
		}

		patternIndex = starIndex + 1
		retryIndex++
		hostIndex = retryIndex
	}

	for patternIndex < len(pattern) && pattern[patternIndex] == '*' {
		patternIndex++
	}

	return patternIndex == len(pattern)
}

func literalHostPattern(pattern string) bool {
	return pattern != "" && pattern[0] != '!' && !strings.ContainsAny(pattern, "*?")
}
