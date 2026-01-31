package main

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type Config struct {
	CIDR       string
	StartPort  int
	EndPort    int
	OutputFile string
	Threads    int
	Timeout    time.Duration
}

type PingResponse struct {
	Version struct {
		Name     string `json:"name"`
		Protocol int    `json:"protocol"`
	} `json:"version"`
	Players struct {
		Max    int `json:"max"`
		Online int `json:"online"`
		Sample []struct {
			Name string `json:"name"`
			ID   string `json:"id"`
		} `json:"sample"`
	} `json:"players"`
	Description interface{} `json:"description"`
	Favicon     string      `json:"favicon"`
}

var (
	outputFileMutex      sync.Mutex
	scannedCount         int64
	foundCount           int64
	errorStats           = make(map[string]int)
	errorStatsMutex      sync.Mutex
	existingServers      = make(map[string]bool)
	existingServersMutex sync.Mutex
)

func main() {
	rand.Seed(time.Now().UnixNano())
	config := parseArgs()

	if config.CIDR == "" || config.StartPort == 0 || config.OutputFile == "" {
		fmt.Println("Usage: ./scan <CIDR> -p <start>-<end> -o <output_file> [-t threads] [-timeout ms]")
		fmt.Println("Example: ./scan 82.26.104.0/24 -p 25565-25565 -o done.txt -t 5000")
		os.Exit(1)
	}

	ips, err := loadTargets(config.CIDR)
	if err != nil {
		fmt.Printf("Error processing input: %v\n", err)
		os.Exit(1)
	}

	loadExistingServers(config.OutputFile)
	fmt.Printf("Loaded %d existing servers from %s\n", len(existingServers), config.OutputFile)

	totalPorts := config.EndPort - config.StartPort + 1
	totalTargets := int64(len(ips) * totalPorts)

	fmt.Printf("Scanning %d IPs, %d ports each.\n", len(ips), totalPorts)
	fmt.Printf("Total targets: %d. Threads: %d. Timeout: %v\n", totalTargets, config.Threads, config.Timeout)

	type Job struct {
		IP   string
		Port int
	}
	jobs := make(chan Job, config.Threads*500)
	var wg sync.WaitGroup

	for i := 0; i < config.Threads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for job := range jobs {
				scanTarget(job.IP, job.Port, config.OutputFile, config.Timeout)
			}
		}()
	}

	startTime := time.Now()

	go func() {
		ticker := time.NewTicker(2 * time.Second)
		defer ticker.Stop()
		for {
			<-ticker.C
			currentScanned := atomic.LoadInt64(&scannedCount)
			currentFound := atomic.LoadInt64(&foundCount)
			elapsed := time.Since(startTime).Seconds()
			if elapsed == 0 {
				elapsed = 1
			}
			rate := float64(currentScanned) / elapsed
			percent := 0.0
			if totalTargets > 0 {
				percent = float64(currentScanned) / float64(totalTargets) * 100
			}

			fmt.Printf("\r\033[2KStatus: %d/%d (%.2f%%) | Found: %d | Speed: %.0f/s | Time: %.0fs",
				currentScanned, totalTargets, percent, currentFound, rate, elapsed)
		}
	}()

	go func() {
		for _, ip := range ips {
			if isBroadcast(ip) {
				atomic.AddInt64(&scannedCount, int64(totalPorts))
				continue
			}
			for port := config.StartPort; port <= config.EndPort; port++ {
				jobs <- Job{IP: ip, Port: port}
			}
		}
		close(jobs)
	}()

	wg.Wait()
	fmt.Println("\nScan complete.")
	fmt.Printf("Total Found: %d\n", atomic.LoadInt64(&foundCount))

	printErrorSummary()
}

func loadExistingServers(filename string) {
	existingServersMutex.Lock()
	defer existingServersMutex.Unlock()

	f, err := os.Open(filename)
	if err != nil {
		if os.IsNotExist(err) {
			return
		}
		return
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		parts := strings.Split(line, " ")
		if len(parts) > 0 {
			key := parts[0]
			existingServers[key] = true
		}
	}
}

func printErrorSummary() {
	errorStatsMutex.Lock()
	defer errorStatsMutex.Unlock()

	if len(errorStats) > 0 {
		fmt.Println("\n[!] Debug: Top errors encountered:")
		for msg, count := range errorStats {
			if count > 0 {
				fmt.Printf(" - %s: %d\n", msg, count)
			}
		}

		for msg := range errorStats {
			if strings.Contains(msg, "too many open files") {
				fmt.Println("\n[CRITICAL] System limit reached (too many open files).")
				fmt.Println("Try running: ulimit -n 100000")
				fmt.Println("Or reduce threads with -t 500")
				break
			}
		}
	}
}

func isBroadcast(ip string) bool {
	if strings.HasSuffix(ip, ".0") || strings.HasSuffix(ip, ".255") {
		return true
	}
	return false
}

func parseArgs() Config {
	config := Config{
		Threads: 10000,
		Timeout: 1 * time.Second,
	}

	args := os.Args[1:]
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if strings.HasPrefix(arg, "-") {
			switch arg {
			case "-p":
				if i+1 < len(args) {
					ports := parsePortRange(args[i+1])
					if len(ports) == 2 {
						config.StartPort = ports[0]
						config.EndPort = ports[1]
					}
					i++
				}
			case "-o":
				if i+1 < len(args) {
					config.OutputFile = args[i+1]
					i++
				}
			case "-t":
				if i+1 < len(args) {
					t, _ := strconv.Atoi(args[i+1])
					if t > 0 {
						config.Threads = t
					}
					i++
				}
			case "-timeout":
				if i+1 < len(args) {
					ms, _ := strconv.Atoi(args[i+1])
					if ms > 0 {
						config.Timeout = time.Duration(ms) * time.Millisecond
					}
					i++
				}
			}
		} else {
			config.CIDR = arg
		}
	}
	return config
}

func loadTargets(input string) ([]string, error) {
	var targets []string

	info, err := os.Stat(input)
	if err == nil && !info.IsDir() {
		file, err := os.Open(input)
		if err != nil {
			return nil, fmt.Errorf("failed to open file: %v", err)
		}
		defer file.Close()

		fmt.Printf("Reading targets from file: %s\n", input)
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" {
				continue
			}
			ips, err := expandCIDR(line)
			if err != nil {
				fmt.Printf("Warning: Skipping invalid line '%s': %v\n", line, err)
				continue
			}
			targets = append(targets, ips...)
		}
		if err := scanner.Err(); err != nil {
			return nil, fmt.Errorf("error reading file: %v", err)
		}
		return targets, nil
	}

	return expandCIDR(input)
}

func parsePortRange(s string) []int {
	parts := strings.Split(s, "-")
	if len(parts) == 2 {
		start, _ := strconv.Atoi(parts[0])
		end, _ := strconv.Atoi(parts[1])
		return []int{start, end}
	}
	if p, err := strconv.Atoi(s); err == nil {
		return []int{p, p}
	}
	return nil
}

func expandCIDR(cidr string) ([]string, error) {
	ip, ipnet, err := net.ParseCIDR(cidr)
	if err == nil {
		var ips []string
		for ip := ip.Mask(ipnet.Mask); ipnet.Contains(ip); inc(ip) {
			ips = append(ips, ip.String())
		}
		return ips, nil
	}

	singleIP := net.ParseIP(cidr)
	if singleIP != nil {
		return []string{cidr}, nil
	}

	return nil, fmt.Errorf("invalid IP or CIDR: %v", err)
}

func inc(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

func scanTarget(ip string, port int, outputFile string, timeout time.Duration) {
	defer atomic.AddInt64(&scannedCount, 1)

	var response *PingResponse
	var err error

	maxRetries := 10
	for i := 0; i < maxRetries; i++ {
		response, err = ping(ip, port, timeout)

		if err == nil {
			break
		}

		msg := err.Error()
		if strings.Contains(msg, "too many open files") || strings.Contains(msg, "resource temporarily unavailable") {
			sleepTime := time.Duration(500+rand.Intn(1000)) * time.Millisecond
			time.Sleep(sleepTime)

			if i == maxRetries-1 {
				logError(err)
			}
			continue
		} else {
			if i == 0 {
				logError(err)
			}
			return
		}
	}

	if err == nil && response != nil {
		atomic.AddInt64(&foundCount, 1)

		motd := parseDescription(response.Description)
		version := response.Version.Name
		online := response.Players.Online
		max := response.Players.Max

		fullLog := fmt.Sprintf("%s:%d -> (%s) - (%d/%d) - (%s)", ip, port, version, online, max, motd)

		fmt.Printf("\r\033[2K%s\n", fullLog)

		saveResult(outputFile, fmt.Sprintf("%s:%d", ip, port), fullLog)
	}
}

func logError(err error) {
	msg := err.Error()
	if strings.Contains(msg, "too many open files") {
		msg = "too many open files"
	} else if strings.Contains(msg, "timeout") {
		msg = "timeout"
	} else if strings.Contains(msg, "connection refused") {
		msg = "connection refused"
	} else if strings.Contains(msg, "no route to host") {
		msg = "no route to host"
	} else {
		if len(msg) > 50 {
			msg = msg[:50] + "..."
		}
	}

	errorStatsMutex.Lock()
	if _, exists := errorStats[msg]; !exists {
		if len(errorStats) >= 10 {
			errorStatsMutex.Unlock()
			return
		}
	}
	errorStats[msg]++
	errorStatsMutex.Unlock()
}

func saveResult(filename, key, content string) {
	existingServersMutex.Lock()
	defer existingServersMutex.Unlock()

	if existingServers[key] {
		return
	}

	f, err := os.OpenFile(filename, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return
	}
	defer f.Close()
	f.WriteString(content + "\n")

	existingServers[key] = true
}

func parseDescription(desc interface{}) string {
	if desc == nil {
		return ""
	}
	switch v := desc.(type) {
	case string:
		return v
	case map[string]interface{}:
		if text, ok := v["text"].(string); ok {
			return text
		}
		if extra, ok := v["extra"].([]interface{}); ok {
			var sb strings.Builder
			for _, e := range extra {
				if eMap, ok := e.(map[string]interface{}); ok {
					if t, ok := eMap["text"].(string); ok {
						sb.WriteString(t)
					}
				} else if eStr, ok := e.(string); ok {
					sb.WriteString(eStr)
				}
			}
			return sb.String()
		}
	}
	return "?"
}

func ping(ip string, port int, timeout time.Duration) (*PingResponse, error) {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", ip, port), timeout)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(timeout))

	handshake := new(bytes.Buffer)
	writeVarInt(handshake, 0x00)
	writeVarInt(handshake, 47)
	writeString(handshake, ip)
	writeUnsignedShort(handshake, uint16(port))
	writeVarInt(handshake, 1)
	sendPacket(conn, handshake.Bytes())

	request := new(bytes.Buffer)
	writeVarInt(request, 0x00)
	sendPacket(conn, request.Bytes())

	r := bufio.NewReader(conn)

	_, err = readVarInt(r)
	if err != nil {
		return nil, err
	}

	packetID, err := readVarInt(r)
	if err != nil {
		return nil, err
	}
	if packetID != 0x00 {
		return nil, fmt.Errorf("bad packet id: %d", packetID)
	}

	jsonStr, err := readString(r)
	if err != nil {
		return nil, err
	}

	var resp PingResponse
	if err := json.Unmarshal([]byte(jsonStr), &resp); err != nil {
		return nil, err
	}

	return &resp, nil
}

func sendPacket(conn net.Conn, data []byte) error {
	buf := new(bytes.Buffer)
	writeVarInt(buf, len(data))
	buf.Write(data)
	_, err := conn.Write(buf.Bytes())
	return err
}

func writeVarInt(w io.ByteWriter, val int) {
	for {
		b := val & 0x7F
		val >>= 7
		if val != 0 {
			b |= 0x80
		}
		w.WriteByte(byte(b))
		if val == 0 {
			break
		}
	}
}

func writeString(w io.Writer, s string) {
	buf := new(bytes.Buffer)
	writeVarInt(buf, len(s))
	buf.WriteString(s)
	w.Write(buf.Bytes())
}

func writeUnsignedShort(w io.Writer, val uint16) {
	binary.Write(w, binary.BigEndian, val)
}

func readVarInt(r io.ByteReader) (int, error) {
	numRead := 0
	result := 0
	for {
		read, err := r.ReadByte()
		if err != nil {
			return 0, err
		}
		value := int(read & 0x7F)
		result |= value << (7 * numRead)
		numRead++
		if numRead > 5 {
			return 0, fmt.Errorf("varint too big")
		}
		if (read & 0x80) == 0 {
			break
		}
	}
	return result, nil
}

func readString(r *bufio.Reader) (string, error) {
	length, err := readVarInt(r)
	if err != nil {
		return "", err
	}

	bytes := make([]byte, length)
	_, err = io.ReadFull(r, bytes)
	if err != nil {
		return "", err
	}
	return string(bytes), nil
}
