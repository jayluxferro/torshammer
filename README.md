## Tor's Hammer
Tor's Hammer is a slow post dos testing tool written in Python. It can also be run through the Tor network to be anonymized. If you are going to run it with Tor it assumes you are running Tor on 127.0.0.1:9050. Kills most unprotected web servers running Apache and IIS via a single instance. Kills Apache 1.X and older IIS with ~128 threads, newer IIS and Apache 2.X with ~256 threads.

## Requirements
This tool is cross-platform because is written in Python. You only need to have python installed on your operating system.

## Installation
- Clone repository.
- Install the tool using the command below.
```bash
python setup.py install
```

## Usage
```bash
torshammer -t <target> [-r <threads> -p <port> -T -h]
-t|--target <Hostname|IP>
-r|--threads <Number of threads> Defaults to 256
-p|--port <Web Server Port> Defaults to 80
-T|--tor Enable anonymising through tor on 127.0.0.1:9050
-h|--help Shows this help

Eg. torshammer -t 192.168.1.100 -r 256
```