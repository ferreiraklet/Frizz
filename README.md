[![made-with-Go](https://img.shields.io/badge/made%20with-Go-brightgreen.svg)](http://golang.org)

<h3 align="center">Find Crlf injection vulnerable endpoints</h3>

<img src="https://cdn.discordapp.com/attachments/876919540682989609/962452079052480592/unknown.png">

---

## Contents:

- [Installation](#installation)
- [Usage](#usage)
  - [Adding Headers](#adding-headers)
  - [Using Proxy](#using-proxy)


## Installation:

Using Go
```bash
▶ go install github.com/ferreiraklet/Frizz@latest
```

From git clone
```bash
▶ git clone https://github.com/ferreiraklet/Frizz.git
▶ cd Frizz
▶ go build frizz.go
▶ chmod +x Frizz
▶ ./Frizz -h
```
<br>


## Usage

Basically, what you need to do is, specify the header value of what you are trying to inject using crlf ->

OBS: The url need protocol, http, https.

#### Stdin - Single URL and from list

```bash
$ echo "http://127.0.0.1:8080/?q=%0d%0aSet-Cookie:crlf=injection" | frizz -payload "crlf=injection"

$ cat targets.txt | frizz -payload "crlf=injection
```

#### Adding Headers

```bash
$ echo "http://127.0.0.1:8080/?q=%0d%0aSet-Cookie:crlf=injection" | frizz -payload "crlf=injection" -H "Customheader1: value1;cheader2: value2"
```

#### Using Proxy
```bash
$ cat targets | frizz -payload "crlf=injection" --proxy "http://yourproxy"

$ cat list.txt | frizz -payload "crlf=injection" --only-poc
```

---
<br>

## Check out some of my other programs <br>

> [Nilo](https://github.com/ferreiraklet/nilo) - Checks if URL has status 200

> [AiriXSS](https://github.com/ferreiraklet/airixss) - Looking for xss reflected

> [Jeeves](https://github.com/ferreiraklet/jeeves) - Time based blind Injection Scanner

## This project is for educational and bug bounty porposes only! I do not support any illegal activities!.

If any error in the program, talk to me immediatly.
