# DomainFuzz

Find similar-looking domain names that adversaries can use to attack you. Can detect typosquatters, phishing attacks, fraud and corporate espionage. Useful as an additional source of targeted threat intelligence.

![Demo](/docs/screenshots/demo.gif)

## Usage

TODO.

## Command util

This project provides a cli tool.

For example, use qq.com as a target:

```bash
node cli.js --target qq.com --format csv --out-put qq.csv -c 10 --modules whois,banners,mxcheck,geoip
```

### Options

* `--target <domain>`            target domain name or URL to check
* `-o --out-put <file>`          Output filename
* `-f --format <type>`           Output format (JSON|CSV) [JSON]
* `-c --concurrency <num>`       start specified NUMBER of concurrency
* `--modules <module>`           Enable modules (whois|banners|mxcheck|ssdeep|geoip)
* `--nameservers <nameservers>`  comma separated list of nameservers to query
* `--dictionary <file>`          generate additional domains using dictionary FILE
* `--registered`                 show only registered domain names (TODO)
* `--can-register`               show only can register domain names (TODO)

## Dependencies

* http://ssdeep.sourceforge.net/
* http://dev.maxmind.com/geoip/geoip2/geolite2/

## Reference

* https://github.com/elceef/dnstwist/
