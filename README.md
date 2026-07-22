# Subdomain Scanner

Find subdomains for a domain by testing common names against DNS. Useful for security reconnaissance and discovering hidden services.

## What it does

Takes a domain name and tries a list of common subdomain prefixes (like www, mail, admin, api, etc.). If DNS resolves a subdomain, it reports the IP address. Uses multiple threads for speed.

## Requirements

Python 3.6+. No external packages needed.

## Usage

Basic scan with default wordlist:
```
python scanner.py example.com
```

Use a custom wordlist:
```
python scanner.py example.com -w wordlist.txt
```

Adjust speed:
```
python scanner.py example.com --threads 100
```

Faster timeout:
```
python scanner.py example.com --timeout 1
```

## Default wordlist

Includes ~130 common subdomain names like:
- Server types: www, mail, ftp, smtp, dns
- Environments: dev, staging, test, beta, prod
- Apps: admin, api, app, dashboard
- DevOps: ci, jenkins, gitlab, docker
- Cloud: cdn, static, assets

## Custom wordlist

Create a text file with one subdomain per line:
```
www
mail
admin
api
dev
```

Then run:
```
python scanner.py example.com -w mylist.txt
```

## License

MIT
