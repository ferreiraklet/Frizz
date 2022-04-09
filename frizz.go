package main

import (
        "bufio"
        "crypto/tls"
        "flag"
        "fmt"
        "net"
        "net/http"
        "net/url"
        "os"
        "strings"
        "sync"
        "time"
)

func init() {
        flag.Usage = func() {
                help := []string{
                        "Airi XSS confirmer",
                        "",
                        "Usage:",
                        "+=======================================================+",
                        "       -header           Header value of crlfi payload",
                        "       -H, --headers,    Headers",
                        "       --proxy,      	  Send traffic to a proxy",
                        "       --only-poc        Show only potentially vulnerable urls",
                        "       -h                Show This Help Message",
                        "",
                        "+=======================================================+",
                        "",
                }

                fmt.Println(`
 ___     _         
|  _|___|_|___ ___ 
|  _|  _| |- _|- _|
|_| |_| |_|___|___|
                   

`)
                fmt.Fprintf(os.Stderr, strings.Join(help, "\n"))

        }

}


func main() {


        var regex string
        flag.StringVar(&regex, "payload","","")

        var proxy string
        flag.StringVar(&proxy,"proxy", "","")

        var poc bool
        flag.BoolVar(&poc,"only-poc", false, "")

        var headers string
        flag.StringVar(&headers,"headers","","")
        flag.StringVar(&headers,"H","","")

        flag.Parse()

        var urls []string
        std := bufio.NewScanner(os.Stdin)
        for std.Scan() {
                var line string = std.Text()
                hline := strings.Replace(line, "%2F", "/", -1)
                line = hline
                // fmt.Println(line)

                urls = append(urls, line)

        }
        var wg sync.WaitGroup
        for _, u := range urls {
                wg.Add(1)
                go func(url string) {

                        defer wg.Done()
                        if proxy != ""{
                            if headers != ""{
                                x := checkCrlf(url, regex, proxy, headers, poc)
                                if x != "ERROR" {
                                    fmt.Println(x)
                                                }
                            }else{
                                x := checkCrlf(url, regex, proxy, "0", poc)
                                if x != "ERROR" {
                                    fmt.Println(x)
                            }
                            }
                        }else{
                                if headers != ""{
                                    x := checkCrlf(url, regex, "0", headers, poc)
                                    if x != "ERROR" {
                                        fmt.Println(x)
                                                    }
                                }else{
                                        x := checkCrlf(url, regex, "0", "0", poc)
                                        if x != "ERROR" {
                                            fmt.Println(x)
                                                        }
                                    }

                            }

                }(u)
        }

        wg.Wait()

}

func checkCrlf(urlt string, regex string, proxy string, headers string, onlypoc bool) string {

        var trans = &http.Transport{
                MaxIdleConns:      30,
                IdleConnTimeout:   time.Second,
                DisableKeepAlives: true,
                TLSClientConfig:   &tls.Config{InsecureSkipVerify: true},
                DialContext: (&net.Dialer{
                        Timeout:   3 * time.Second,
                        KeepAlive: time.Second,
                }).DialContext,
        }

        client := &http.Client{
                Transport: trans,
                Timeout:   3 * time.Second,
        }

        _, err := url.Parse(urlt)
        if err != nil{
            return "ERROR"
        }

        if proxy != "0" {
            if p, err := url.Parse(proxy); err == nil {
                trans.Proxy = http.ProxyURL(p)
        }}

        res, err := http.NewRequest("GET", urlt, nil)
        res.Header.Set("User-Agent","Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/97.0.4692.71 Safari/537.36")
        //res.Header.Set("Connection", "close")
        if headers != "0"{
            if strings.Contains(headers, ";"){
                    parts := strings.Split(headers, ";")
                    for _, q := range parts{
                        separatedHeader := strings.Split(q,":")
                        res.Header.Set(separatedHeader[0],separatedHeader[1])
        }
        }else{
            sHeader := strings.Split(headers,":")
            res.Header.Set(sHeader[0], sHeader[1])
}
}


        resp, err := client.Do(res)

        if err != nil {
                return "ERROR"
        }
        defer resp.Body.Close()

        
        //re := `.*?Set-Cookie\s*?:(?:\s*?|.*?;\s*?)(`+regex+`)`
        //reg := regexp.MustCompile(re)
        

        for _, header := range resp.Header{
            for _, v := range header{
                //fmt.Println(v)
                if strings.Contains(v, regex){

                    if onlypoc != false{
                        return urlt
                    }else{
                        return "\033[1;31m[VULN!] "+urlt+"\033[0;0m"
                        }             

                    }


                }
            }
        

        if onlypoc != false{
            return "ERROR"
        }else{
            return "\033[1;30m[NOTVULN;-;] "+urlt+"\033[0;0m"
            }
     

       
}