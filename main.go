package main

import (
	"bufio"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"github.com/leolovenet/ipqqwry/qqwry"
	"net"
	"net/url"
	"os"
	"regexp"
	"strings"
)

type (
	Info struct {
		Domain  string `json:"domain ,omitempty"`
		IP      string `json:"ip     "`
		Country string `json:"country"`
		Area    string `json:"area   "`
	}
)

var (
	Version   string
	BuildTime string
)

func main() {
	ipdb, err := qqwry.New(os.Getenv("IPDB_QQWRY_PATH"))
	if err != nil {
		panic(err)
	}

	var (
		result []Info
		v      interface{}
	)

	stdinStat, err := os.Stdin.Stat()
	if err != nil {
		panic(err)
	}

	if stdinStat.Mode()&os.ModeNamedPipe != 0 {
		var (
			// https://en.wikipedia.org/wiki/ANSI_escape_code#Colors
			outputWithColor   = false
			translateNoPublic = false

			regexMacAddress = regexp.MustCompile(`[a-fA-F0-9]{2}([:-][a-fA-F0-9]{2}){5}`)
			regexIPv4       = regexp.MustCompile(`(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)){3}`)

			// Modified from https://community.helpsystems.com/forums/intermapper/miscellaneous-topics/5acc4fcf-fa83-e511-80cf-0050568460e4
			//          Demo https://regex101.com/r/Lr17T7/1
			regexIPv6 = regexp.MustCompile(`((([0-9A-Fa-f]{1,4}:){7}([0-9A-Fa-f]{1,4}|:))|(([0-9A-Fa-f]{1,4}:){6}(:[0-9A-Fa-f]{1,4}|((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){5}(((:[0-9A-Fa-f]{1,4}){1,2})|:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){4}(((:[0-9A-Fa-f]{1,4}){1,3})|((:[0-9A-Fa-f]{1,4})?:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){3}(((:[0-9A-Fa-f]{1,4}){1,4})|((:[0-9A-Fa-f]{1,4}){0,2}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){2}(((:[0-9A-Fa-f]{1,4}){1,5})|((:[0-9A-Fa-f]{1,4}){0,3}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|([0-9A-Fa-f]{1,4}:)(((:[0-9A-Fa-f]{1,4}){0,4}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|((:[0-9A-Fa-f]{1,4}){1,6})|:)|(:(((:[0-9A-Fa-f]{1,4}){1,7})|((:[0-9A-Fa-f]{1,4}){0,5}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:)))`)
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

		scanner := bufio.NewScanner(os.Stdin)
		for scanner.Scan() {
			line := scanner.Text()

			if outputWithColor {
				line = ReplaceAllString(regexMacAddress, line, func(b byte) bool {
					if (b >= '0' && b <= '9') || (b >= 'a' && b <= 'f') ||
						(b >= 'A' && b <= 'F') || b == ':' || b == '-' {
						return false
					}
					return true
				}, func(str string) (string, int) {
					return fmt.Sprintf("\033[33m%s\033[0m", str), 0
				})

				line = ReplaceAllString(regexIPv6, line, func(b byte) bool {
					if (b >= '0' && b <= '9') || (b >= 'a' && b <= 'f') ||
						(b >= 'A' && b <= 'F') || b == ':' || b == '.' {
						return false
					}
					return true
				}, func(str string) (string, int) {
					return fmt.Sprintf("\033[34m%s\033[0m", str), 0
				})
			}

			line = ReplaceAllString(regexIPv4, line, func(b byte) bool {
				if b >= '0' && b <= '9' {
					return false
				}
				return true
			}, func(str string) (string, int) {
				var (
					info    string
					incrLen int
					err     error
				)

				if (translateNoPublic || IsPublicIPv4(str)) &&
					!strings.HasPrefix(str, "0.") &&
					!strings.HasPrefix(str, "255.") {
					info, err = ipdb.QueryInfo(str)
					if err != nil {
						_, _ = fmt.Fprintln(os.Stderr, "!!!!  "+str, err)
					} else {
						info = strings.ReplaceAll(strings.ReplaceAll(info, "(", "["), ")", "]")
						incrLen = len(info) + 2 // within "()"

						if outputWithColor {
							info = fmt.Sprintf("\033[0m(\033[90m%s\033[0m)", info)
						} else {
							info = fmt.Sprintf("(%s)", info)
						}
					}
				}

				if outputWithColor {
					str = fmt.Sprintf("\033[35m%s\033[0m", str)
				}

				return fmt.Sprintf("%s%s", str, info), incrLen
			})

			fmt.Println(line)
		}

		if err := scanner.Err(); err != nil {
			panic(err)
		}

		os.Exit(0)
	}

	if len(os.Args) < 2 {
		fmt.Println("Usage: ")
		fmt.Println("  ipqqwry [ip | domain] ...")
		fmt.Println("  ifconfig | ipqqwry [-p | -C]    Using pipeline, translate the included ip address information.")
		fmt.Println("                                  The -p option also translates(default not) non-public IP information.")
		fmt.Println("                                  The -C option suppress color output.")
		fmt.Println("  ipqqwry [-v | version]          show qqwry version.")
		os.Exit(1)
	}

	for i := 1; i < len(os.Args); i++ {
		if strings.HasPrefix(os.Args[i], "-v") || os.Args[i] == "version" {
			fmt.Println("qqwry: " + ipdb.Version())
			fmt.Println("Version: " + Version)
			fmt.Println("BuildTime: " + BuildTime)
			os.Exit(0)
		}
	}

	for i := 1; i < len(os.Args); i++ {
		input := os.Args[i]
		ip := net.ParseIP(input).To4()
		if ip != nil {
			base, ext, err := ipdb.QueryIP(ip)
			if err != nil {
				panic(err)
			}
			result = append(result, Info{
				IP:      input,
				Country: base,
				Area:    ext,
			})
		} else {
			if strings.HasPrefix(input, "http") {
				u, err := url.Parse(input)
				if err != nil {
					fmt.Println(err)
					continue
				}
				input = u.Hostname()
			}

			ips, err := net.LookupIP(input)
			if err != nil {
				fmt.Println(err)
				continue
			}

			for _, v := range ips {
				if ipv4 := v.To4(); ipv4 != nil {
					base, ext, err := ipdb.QueryIP(ipv4)
					if err != nil {
						panic(err)
					}

					result = append(result, Info{
						Domain:  input,
						IP:      v.String(),
						Country: base,
						Area:    ext,
					})
				}
			}
		}
	}

	v = result
	if len(result) == 1 {
		v = result[0]
	}

	output, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		panic(err)
	}

	fmt.Println(string(output))
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

func ReplaceAllString(re *regexp.Regexp, src string, borderPass func(b byte) bool, repl func(string) (string, int)) string {
	loc := re.FindAllStringIndex(src, -1)
	if loc == nil {
		return src
	}

	var (
		buf  string
		last = 0
	)

	for _, v := range loc {
		idx0 := v[0] - 1
		idx1 := v[1]
		if (idx0 >= 0 && !borderPass(src[idx0])) || (idx1 < len(src) && !borderPass(src[idx1])) {
			return src
		}

		buf += src[last:v[0]]
		matchRepl, incrLen := repl(src[v[0]:v[1]])
		buf += matchRepl

		last = v[1]
		for i := v[1]; i < v[1]+incrLen; i++ {
			if i >= len(src) || src[i] != ' ' || src[i+1] != ' ' {
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
