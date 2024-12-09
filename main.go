package main

import (
	"bufio"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"os"
	"regexp"
	"runtime"
	"strings"

	"github.com/leolovenet/ipqqwry/qqwry"
)

type (
	Info struct {
		Domain  string `json:"domain,omitempty"`
		IP      string `json:"ip"`
		Area    string `json:"area"`
		Country string `json:"country"`
	}
)

var (
	Version   string
	BuildTime string
)

var (
	ColorYellow = "\033[33m"
	ColorBlue   = "\033[34m"
	ColorPurple = "\033[35m"
	ColorCyan   = "\033[36m"
	ColorGray   = "\033[90m"
	ColorReset  = "\033[0m"
)

func printUsage() {
	fmt.Println("Usage: ")
	fmt.Println("  ipqqwry [ip | domain] ...")
	fmt.Println("  ifconfig | ipqqwry [-p | -C]             Using pipeline, translate the included MAC/IPv4/IPv6 address information.")
	fmt.Println("                                           The -p option also translates(default not) non-public IPv4 information.")
	fmt.Println("                                           The -C option suppress color output.")
	fmt.Println("  ipqqwry < file                           Using Input redirection, translate the included MAC/IPv4/IPv6 address information.")
	fmt.Println("  ipqqwry [-v | --version | version]       show qqwry version.")
	fmt.Println("  ipqqwry [-h | --help | help]             show this help.")
}

func main() {
	ipdb, err := qqwry.New(os.Getenv("IPDB_QQWRY_PATH"))
	if err != nil {
		panic(err)
	}

	for i := 1; i < len(os.Args); i++ {
		if strings.HasPrefix(os.Args[i], "-v") || os.Args[i] == "--version" || os.Args[i] == "version" {
			fmt.Println("qqwry: " + ipdb.Version())
			fmt.Println("Version: " + Version)
			fmt.Println("BuildTime: " + BuildTime)
			os.Exit(0)
		}
		if strings.HasPrefix(os.Args[i], "-h") || os.Args[i] == "--help" || os.Args[i] == "help" {
			printUsage()
			os.Exit(0)
		}
	}

	staticHosts, err := ParseHostsFile(true)
	if err != nil {
		fmt.Printf("Error parsing hosts file: %v\n", err)
	}

	{
		stdinStat, err := os.Stdin.Stat()
		if err != nil {
			panic("Error getting stdin stat: " + err.Error())
		}
		if stdinStat.Mode()&os.ModeNamedPipe != 0 || stdinStat.Mode()&(os.ModeDevice|os.ModeCharDevice) == 0 {
			var (
				// https://en.wikipedia.org/wiki/ANSI_escape_code#Colors
				outputWithColor   = false
				translateNoPublic = false
				regexMacAddress   = regexp.MustCompile(`[a-fA-F0-9]{2}([:-][a-fA-F0-9]{2}){5}`)
				//                                                                                                                  tailer
				regexIPv4 = regexp.MustCompile(`(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)){3}((\:|\.|\/)\d+)?`)
				// Modified from https://community.helpsystems.com/forums/intermapper/miscellaneous-topics/5acc4fcf-fa83-e511-80cf-0050568460e4
				//          Demo https://regex101.com/r/Lr17T7/1
				//                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      tailer
				regexIPv6 = regexp.MustCompile(`((([0-9A-Fa-f]{1,4}:){7}([0-9A-Fa-f]{1,4}|:))|(([0-9A-Fa-f]{1,4}:){6}(:[0-9A-Fa-f]{1,4}|((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){5}(((:[0-9A-Fa-f]{1,4}){1,2})|:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){4}(((:[0-9A-Fa-f]{1,4}){1,3})|((:[0-9A-Fa-f]{1,4})?:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){3}(((:[0-9A-Fa-f]{1,4}){1,4})|((:[0-9A-Fa-f]{1,4}){0,2}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){2}(((:[0-9A-Fa-f]{1,4}){1,5})|((:[0-9A-Fa-f]{1,4}){0,3}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|([0-9A-Fa-f]{1,4}:)(((:[0-9A-Fa-f]{1,4}){0,4}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|((:[0-9A-Fa-f]{1,4}){1,6})|:)|(:(((:[0-9A-Fa-f]{1,4}){1,7})|((:[0-9A-Fa-f]{1,4}){0,5}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:)))((\]\:|\%|\/|\.)\w+)?`)
			)

			if stdoutStat, _ := os.Stdout.Stat(); (stdoutStat.Mode() & os.ModeCharDevice) != 0 {
				outputWithColor = true
			}

			for i := 1; i < len(os.Args); i++ {
				if strings.HasPrefix(os.Args[i], "-p") || strings.HasPrefix(os.Args[i], "-Cp") {
					translateNoPublic = true
				}
				if strings.HasPrefix(os.Args[i], "-C") || strings.HasPrefix(os.Args[i], "-pC") {
					outputWithColor = false
				}
			}

			writer := bufio.NewWriter(os.Stdout)
			defer writer.Flush()

			scanner := bufio.NewScanner(os.Stdin)
			for scanner.Scan() {
				line := scanner.Text()

				if outputWithColor {
					line = ReplaceAllString(regexMacAddress, line,
						func(b byte, before bool, idx []int) bool { //borderCheck
							// `b` can't be those characters
							if (b >= '0' && b <= '9') || (b >= 'a' && b <= 'f') ||
								(b >= 'A' && b <= 'F') || b == ':' || b == '-' {
								return false
							}
							return true
						},
						func(idx []int) (string, int) { //repl
							return fmt.Sprintf("%s%s%s", ColorYellow, line[idx[0]:idx[1]], ColorReset), 0
						},
					)

					line = ReplaceAllString(regexIPv6, line,
						func(b byte, before bool, idx []int) bool { //borderCheck
							// if is befor character or don't have tailer
							if (before || idx[len(idx)-1] == -1) && b == ':' {
								return false
							}
							// `b` can't be those characters
							if (b >= '0' && b <= '9') || (b >= 'a' && b <= 'f') || (b >= 'A' && b <= 'F') {
								return false
							}
							return true
						},
						func(idx []int) (string, int) { //repl
							tailStr := ""
							tailSub := ""
							tailLen := 0
							idxLen := len(idx)
							if idx[idxLen-1] != -1 {
								tailLen = idx[idxLen-3] - idx[idxLen-4]
								tailSub = line[idx[idxLen-2]:idx[idxLen-1]]                // step chart
								tailStr = line[idx[idxLen-4]+len(tailSub) : idx[idxLen-3]] // skip "step" chart
								tailStr = fmt.Sprintf("%s%s%s%s", tailSub, ColorCyan, tailStr, ColorReset)
							}

							return fmt.Sprintf("%s%s%s%s", ColorBlue, line[idx[0]:idx[1]-tailLen], ColorReset, tailStr), 0
						},
					)
				}

				line = ReplaceAllString(regexIPv4, line,
					func(b byte, before bool, idx []int) bool { //borderCheck
						// if is befor character or don't have tailer
						if (before || idx[len(idx)-1] == -1) && b == '.' {
							return false
						}
						// `b` can't be those characters
						if b >= '0' && b <= '9' {
							return false
						}
						return true
					},
					func(idx []int) (string, int) { //repl
						var (
							info    string
							incrLen int
							err     error
						)

						tailStr := ""
						tailSub := ""
						tailLen := 0
						idxLen := len(idx)
						if idx[idxLen-1] != -1 {
							tailLen = idx[idxLen-3] - idx[idxLen-4]
							tailSub = line[idx[idxLen-2]:idx[idxLen-1]]                // step chart
							tailStr = line[idx[idxLen-4]+len(tailSub) : idx[idxLen-3]] // skip "step" chart
							if outputWithColor {
								tailStr = fmt.Sprintf("%s%s%s", ColorCyan, tailStr, ColorReset)
							}
							tailStr = fmt.Sprintf("%s%s", tailSub, tailStr)
						}

						ipStr := line[idx[0] : idx[1]-tailLen]
						if (translateNoPublic || IsPublicIPv4(ipStr)) &&
							!strings.HasPrefix(ipStr, "0.") &&
							!strings.HasPrefix(ipStr, "255.") {
							info, err = ipdb.QueryInfo(ipStr)
							if err != nil {
								_, _ = fmt.Fprintln(os.Stderr, "!!!!  "+ipStr, err)
							} else {
								if info2, ok := staticHosts[ipStr]; ok {
									if outputWithColor {
										info2 = fmt.Sprintf("%s%s%s", ColorYellow, info2, ColorReset)
									}
									info = fmt.Sprintf("%s%s|%s", info, ColorReset, info2)
								}
								info = strings.ReplaceAll(strings.ReplaceAll(info, "(", "["), ")", "]")

								incrLen = len(info) + 2 // within "()"

								if outputWithColor {
									info = fmt.Sprintf("%s(%s%s%s)", ColorReset, ColorGray, info, ColorReset)
								} else {
									info = fmt.Sprintf("(%s)", info)
								}
							}
						}

						if outputWithColor {
							ipStr = fmt.Sprintf("%s%s%s", ColorPurple, ipStr, ColorReset)
						}

						return fmt.Sprintf("%s%s%s", ipStr, info, tailStr), incrLen
					},
				)

				fmt.Println(line)
				writer.Flush()
			}

			if err := scanner.Err(); err != nil {
				panic(err)
			}
		} else {
			if len(os.Args) < 2 {
				printUsage()
				os.Exit(1)
			}
		}
	}

	var outputData []Info
	for i := 1; i < len(os.Args); i++ {
		input := os.Args[i]
		ip := net.ParseIP(input).To4()
		if ip != nil {
			base, ext, err := ipdb.QueryIP(ip)
			if err != nil {
				panic(err)
			}
			if base2, ok := staticHosts[input]; ok {
				base = fmt.Sprintf("%s|%s", base, base2)
			}
			outputData = append(outputData, Info{
				IP:      input,
				Country: base,
				Area:    ext,
			})
		} else {
			if strings.HasPrefix(input, "http") {
				u, err := url.Parse(input)
				if err != nil {
					fmt.Printf("Error parsing URL: %s, Error: %s, Skip it.\n", input, err)
					continue
				}
				input = u.Hostname()
			}

			ips, err := net.LookupIP(input)
			if err != nil {
				fmt.Printf("Error looking up IP: %s, Error: %s, Skip it.\n", input, err)
				continue
			}

			for _, v := range ips {
				if ipv4 := v.To4(); ipv4 != nil {
					base, ext, err := ipdb.QueryIP(ipv4)
					if err != nil {
						panic(err)
					}
					ipv4Str := ipv4.String()
					if base2, ok := staticHosts[ipv4Str]; ok {
						base = fmt.Sprintf("%s|%s", base, base2)
					}
					outputData = append(outputData, Info{
						Domain:  input,
						IP:      v.String(),
						Country: base,
						Area:    ext,
					})
				}
			}
		}
	}

	if len(outputData) > 0 {
		output, err := json.MarshalIndent(outputData, "", "  ")
		if err != nil {
			panic(err)
		}
		fmt.Println(string(output))
	}
}

func IP2long(ip net.IP) uint32 {
	if len(ip) == 16 {
		return binary.BigEndian.Uint32(ip[12:16])
	}

	return binary.BigEndian.Uint32(ip)
}

func Long2ip(nn uint32) net.IP {
	ip := make(net.IP, 4)
	binary.BigEndian.PutUint32(ip, nn)

	return ip
}

func IsPublicIPv4Long(ipLong uint32) bool {
	//https://en.wikipedia.org/wiki/IPv4#Special-use_addresses
	switch {
	case ipLong <= uint32(16777215): //0.0.0.0–0.255.255.255
		return false
	case ipLong >= uint32(167772160) && ipLong <= uint32(184549375): //10.0.0.0–10.255.255.255
		return false
	case ipLong >= uint32(1681915904) && ipLong <= uint32(1686110207): //100.64.0.0–100.127.255.255
		return false
	case ipLong >= uint32(2130706432) && ipLong <= uint32(2147483647): //127.0.0.0–127.255.255.255
		return false
	case ipLong >= uint32(2851995648) && ipLong <= uint32(2852061183): //169.254.0.0–169.254.255.255
		return false
	case ipLong >= uint32(2886729728) && ipLong <= uint32(2887778303): //172.16.0.0–172.31.255.255
		return false
	case ipLong >= uint32(3221225472) && ipLong <= uint32(3221225727): //192.0.0.0–192.0.0.255
		return false
	case ipLong >= uint32(3221225984) && ipLong <= uint32(3221226239): //192.0.2.0–192.0.2.255
		return false
	case ipLong >= uint32(3227017984) && ipLong <= uint32(3227018239): //192.88.99.0–192.88.99.255
		return false
	case ipLong >= uint32(3232235520) && ipLong <= uint32(3232301055): //192.168.0.0–192.168.255.255
		return false
	case ipLong >= uint32(3323068416) && ipLong <= uint32(3323199487): //198.18.0.0–198.19.255.255
		return false
	case ipLong >= uint32(3325256704) && ipLong <= uint32(3325256959): //198.51.100.0–198.51.100.255
		return false
	case ipLong >= uint32(3405803776) && ipLong <= uint32(3405804031): //203.0.113.0–203.0.113.255
		return false
	case ipLong >= uint32(3758096384) && ipLong <= uint32(4026531839): //224.0.0.0–239.255.255.255
		return false
	case ipLong >= uint32(4026531840) && ipLong <= uint32(4294967294): //240.0.0.0–255.255.255.254
		return false
	case ipLong == uint32(4294967295): //255.255.255.255
		return false
	}

	return true
}

func IsPublicIPv4(IP string) bool {
	ip := net.ParseIP(IP)
	if ip == nil {
		return false
	}

	return IsPublicIPv4Long(IP2long(ip))
}

func ReplaceAllString(re *regexp.Regexp, src string, borderCheck func(byte, bool, []int) bool, repl func([]int) (string, int)) string {
	loc := re.FindAllStringSubmatchIndex(src, -1)
	if loc == nil {
		return src
	}

	var buf string
	var last int
	for _, v := range loc {
		beforeCharIdx := v[0] - 1
		afterCharIdx := v[1]
		if (beforeCharIdx >= 0 && !borderCheck(src[beforeCharIdx], true, v)) ||
			(afterCharIdx < len(src) && !borderCheck(src[afterCharIdx], false, v)) {
			continue
		}

		buf += src[last:v[0]]
		matchRepl, incrLen := repl(v)
		buf += matchRepl

		last = v[1]
		for i := v[1]; i < v[1]+incrLen; i++ {
			if i >= len(src) || src[i] != ' ' || (i+1 < len(src) && src[i+1] != ' ') {
				break
			}
			last = i
		}
	}

	if last != len(src) {
		buf += src[last:]
	}

	return buf
}

func GetHostsFilePath() string {
	switch runtime.GOOS {
	case "windows":
		return "C:\\Windows\\System32\\drivers\\etc\\hosts"
	case "linux", "darwin":
		return "/etc/hosts"
	default:
		return "/etc/hosts" // Default to Unix-like systems
	}
}

// ParseHostsFile parses the hosts file and returns a map of hostname to IP address
func ParseHostsFile(reverse bool) (map[string]string, error) {
	filePath := GetHostsFilePath()
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	hosts := make(map[string]string)
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		// Skip comments and empty lines
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) >= 2 {
			ip := fields[0]
			if reverse {
				hosts[ip] = fields[1]
			} else {
				for _, hostname := range fields[1:] {
					hosts[hostname] = ip
				}
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return hosts, nil
}
