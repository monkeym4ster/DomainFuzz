const url = require('url');
const fs = require('fs');
const net = require('net');
const dns = require('dns');
const Promise = require('bluebird');
const debug = require('debug')('fuzz:fuzz');
const request = require('request');
const libssdeep = require('ssdeep');
const libwhois = require('whois-json');
const nodemailer = require('nodemailer');
const { printError, bye, rsplit } = require('./utils');
const CONF = require('../config');
const geoip2 = require('geoip2');

geoip2.init(CONF.GEOIP_FILE);

class DomainFuzz {
  constructor(domain) {
    [this.domain, this.tld] = this.__domain_tld(domain);
    if (!this.tld) {
      printError('Target invalid.');
      bye(-1);
    }
    this.domains = [];

    this.qwerty = {
      1: '2q', 2: '3wq1', 3: '4ew2', 4: '5re3', 5: '6tr4', 6: '7yt5', 7: '8uy6', 8: '9iu7', 9: '0oi8', 0: 'po9',
      q: '12wa', w: '3esaq2', e: '4rdsw3', r: '5tfde4', t: '6ygfr5', y: '7uhgt6', u: '8ijhy7', i: '9okju8', o: '0plki9', p: 'lo0',
      a: 'qwsz', s: 'edxzaw', d: 'rfcxse', f: 'tgvcdr', g: 'yhbvft', h: 'ujnbgy', j: 'ikmnhu', k: 'olmji', l: 'kop',
      z: 'asx', x: 'zsdc', c: 'xdfv', v: 'cfgb', b: 'vghn', n: 'bhjm', m: 'njk',
    };
    this.qwertz = {
      1: '2q', 2: '3wq1', 3: '4ew2', 4: '5re3', 5: '6tr4', 6: '7zt5', 7: '8uz6', 8: '9iu7', 9: '0oi8', 0: 'po9',
      q: '12wa', w: '3esaq2', e: '4rdsw3', r: '5tfde4', t: '6zgfr5', z: '7uhgt6', u: '8ijhz7', i: '9okju8', o: '0plki9', p: 'lo0',
      a: 'qwsy', s: 'edxyaw', d: 'rfcxse', f: 'tgvcdr', g: 'zhbvft', h: 'ujnbgz', j: 'ikmnhu', k: 'olmji', l: 'kop',
      y: 'asx', x: 'ysdc', c: 'xdfv', v: 'cfgb', b: 'vghn', n: 'bhjm', m: 'njk',
    };
    this.azerty = {
      1: '2a', 2: '3za1', 3: '4ez2', 4: '5re3', 5: '6tr4', 6: '7yt5', 7: '8uy6', 8: '9iu7', 9: '0oi8', 0: 'po9',
      a: '2zq1', z: '3esqa2', e: '4rdsz3', r: '5tfde4', t: '6ygfr5', y: '7uhgt6', u: '8ijhy7', i: '9okju8', o: '0plki9', p: 'lo0m',
      q: 'zswa', s: 'edxwqz', d: 'rfcxse', f: 'tgvcdr', g: 'yhbvft', h: 'ujnbgy', j: 'iknhu', k: 'olji', l: 'kopm', m: 'lp',
      w: 'sxq', x: 'zsdc', c: 'xdfv', v: 'cfgb', b: 'vghn', n: 'bhj',
    };

    this.keyboards = [this.qwerty, this.qwertz, this.azerty];
  }

  __domain_tld(domain) {
    domain = rsplit(domain, '.', 2);
    if (domain.length === 2) {
      return [domain[0], domain[1]];
    }
    const cc_tld = {};
    const re_tld = /^[a-z]{2,4}\.[a-z]{2}$/i;

    const data = fs.readFileSync(CONF.TLD_FILE);
    const lines = data.toString().split('\n');
    for (const line of lines) {
      if (re_tld.test(line)) {
        const [sld, tld] = line.split('.');
        if (!Reflect.has(cc_tld, tld)) {
          cc_tld[tld] = [];
        }
        cc_tld[tld].push(sld);
      }
    }
    const sld_tld = Reflect.get(cc_tld, domain[2]);
    if (sld_tld) {
      if (sld_tld.includes(domain[1])) {
        return [domain[0], domain[1] + '.' + domain[2]];
      }
    }
    return [`${domain[0]}.${domain[1]}`, domain[2]];
  }

  __validate_domain() {
    let domain = this.domain;
    if (domain.endsWith('.')) {
      domain = domain.substr(0, domain.length - 1);
    }
    if (domain.length > 255) {
      return false;
    }
    return true;
  }

  __filter_domains() {
    const domains = this.domains;
    const seen = new Set();
    const filtered = [];
    for (const domain of domains) {
      if (this.__validate_domain(domain['domain-name']) && !seen.has(domain['domain-name'])) {
        seen.add(domain['domain-name']);
        filtered.push(domain);
      }
    }
    return filtered;
  }

  __bitsquatting() {
    const domain = this.domain;
    const result = [];
    const masks = [1, 2, 4, 8, 16, 32, 64, 128];
    for (let i = 0; i < domain.length; i++) {
      const c = domain[i];
      for (let j = 0; j < masks.length; j++) {
        const b = String.fromCharCode(c.charCodeAt() ^ masks[j]);
        const o = b.charCodeAt();
        if ((o >= 48 && o <= 57) || (o >= 97 && o <= 122) || o === 45) {
          result.push(domain.substr(0, i) + b + domain.substr(i + 1));
        }
      }
    }
    return result;
  }


  __homoglyph() {
    const domain = this.domain;
    const glyphs = {
      a: ['à', 'á', 'â', 'ã', 'ä', 'å', 'ɑ', 'а', 'ạ'],
      b: ['d', 'lb', 'ib', 'ʙ', 'Ь', 'ｂ'],
      c: ['ϲ', 'с', 'ⅽ', 'ƈ', 'ċ', 'ć'],
      d: ['b', 'cl', 'dl', 'di', 'ԁ', 'ժ', 'ⅾ', 'ｄ', 'ɗ'],
      e: ['é', 'ê', 'ë', 'ē', 'ĕ', 'ė', 'ｅ', 'е', 'ẹ', 'ę'],
      f: ['Ϝ', 'Ｆ', 'ｆ'],
      g: ['q', 'ɢ', 'ɡ', 'Ԍ', 'Ԍ', 'ｇ', 'ġ'],
      h: ['lh', 'ih', 'һ', 'ｈ'],
      i: ['1', 'l', 'Ꭵ', 'ⅰ', 'ｉ', 'í', 'ï'],
      j: ['ј', 'ｊ', 'ʝ'],
      k: ['lk', 'ik', 'lc', 'κ', 'ｋ'],
      l: ['1', 'i', 'ⅼ', 'ｌ'],
      m: ['n', 'nn', 'rn', 'rr', 'ṃ', 'ⅿ', 'ｍ'],
      n: ['m', 'r', 'ｎ', 'ń'],
      o: ['0', 'Ο', 'ο', 'О', 'о', 'Օ', 'Ｏ', 'ｏ', 'ȯ', 'ọ', 'ỏ', 'ơ', 'ó'],
      p: ['ρ', 'р', 'ｐ'],
      q: ['g', 'ｑ', 'զ'],
      r: ['ʀ', 'ｒ'],
      s: ['Ⴝ', 'Ꮪ', 'Ｓ', 'ｓ', 'ʂ', 'ś'],
      t: ['τ', 'ｔ'],
      u: ['μ', 'υ', 'Ս', 'Ｕ', 'ｕ', 'ս'],
      v: ['ｖ', 'ѵ', 'ⅴ', 'ν'],
      w: ['vv', 'ѡ', 'ｗ'],
      x: ['ⅹ', 'ｘ', 'х', 'ҳ'],
      y: ['ʏ', 'γ', 'у', 'Ү', 'ｙ', 'ý'],
      z: ['ｚ', 'ʐ', 'ż', 'ź', 'ʐ'],
    };
    const result = [];
    for (let ws = 0; ws < domain.length; ws++) {
      for (let i = 0; i < (domain.length - ws + 1); i++) {
        let win = domain.substr(i, ws);
        let j = 0;
        while (j < ws) {
          const c = win[j];
          if (Reflect.has(glyphs, c)) {
            const win_copy = win;
            for (const _ in glyphs[c]) {
              const g = glyphs[c][_];
              win = win.replace(c, g);
              result.push(`${domain.substr(0, i)}${win}${domain.substr(i + ws)}`);
              win = win_copy;
            }
          }
          j += 1;
        }
      }
    }
    return Array.from(new Set(result));
  }

  __hyphenation() {
    const domain = this.domain;
    const result = [];
    for (let i = 1; i < domain.length; i++) {
      const _ = `${domain.substr(0, i)}-${domain.substr(i)}`;
      result.push(_);
    }
    return result;
  }

  __insertion() {
    const domain = this.domain;
    const keyboards = this.keyboards;

    const result = [];
    for (let i = 1; i < domain.length - 1; i++) {
      for (const keys of keyboards) {
        if (Reflect.has(keys, (domain.substr(i, 1)))) {
          for (const c of keys[domain.substr(i, 1)]) {
            result.push(domain.substr(0, i) + c + domain.substr(i, 1) + domain.substr(i + 1));
            result.push(domain.substr(0, i) + domain.substr(i, 1) + c + domain.substr(i + 1));
          }
        }
      }
    }
    return Array.from(new Set(result));
  }

  __omission() {
    const domain = this.domain;
    const result = [];
    if (domain.length > 1) {
      for (let i = 0; i < domain.length; i++) {
        result.push(domain.substr(0, i) + domain.substr(i + 1));
      }
    }
    return Array.from(new Set(result));
  }

  __repetition() {
    const domain = this.domain;
    const result = [];
    for (let i = 0; i < domain.length; i++) {
      result.push(domain.substr(0, i) + domain.substr(i, 1) + domain.substr(i, 1) + domain.substr(i + 1));
    }
    return Array.from(new Set(result));
  }

  __replacement() {
    const domain = this.domain;
    const keyboards = this.keyboards;
    const result = [];
    for (let i = 0; i < domain.length; i++) {
      for (const keys of keyboards) {
        if (Reflect.has(keys, (domain.substr(i, 1)))) {
          for (const c of keys[domain.substr(i, 1)]) {
            result.push(domain.substr(0, i) + c + domain.substr(i + 1));
          }
        }
      }
    }
    return Array.from(new Set(result));
  }

  __subdomain() {
    const domain = this.domain;
    const result = [];
    for (let i = 1; i < domain.length; i++) {
      if (!['-', '.'].includes(domain.substr(i, 1)) && !['-', '.'].includes(domain.substr(i + 1, 1))) {
        result.push(`${domain.substr(0, i)}.${domain.substr(i)}`);
      }
    }
    return Array.from(new Set(result));
  }

  __transposition() {
    const domain = this.domain;
    const result = [];
    for (let i = 0; i < domain.length - 1; i++) {
      if (domain.substr(i + 1, 1) !== domain.substr(i, 1)) {
        result.push(domain.substr(0, i) + domain.substr(i + 1, 1) + domain.substr(i, 1) + domain.substr(i + 2));
      }
    }
    return Array.from(new Set(result));
  }

  __vowel_swap() {
    const domain = this.domain;
    const vowels = 'aeiou';
    const result = [];
    for (let i = 0; i < domain.length; i++) {
      for (const vowel of vowels) {
        if (vowels.includes(domain.substr(i, 1))) {
          result.push(domain.substr(0, i) + vowel + domain.substr(i + 1));
        }
      }
    }
    return Array.from(new Set(result));
  }

  __addition() {
    const domain = this.domain;
    const result = [];
    for (let i = 97; i < 123; i++) {
      result.push(domain + String.fromCharCode(i));
    }
    return Array.from(new Set(result));
  }

  __various() {
    const domain = this.domain;
    const prefixs = ['ww', 'www', 'www-'];
    const result = [];
    for (const prefix of prefixs) {
      result.push(prefix + domain);
    }
    return result;
  }

  generate() {
    this.domains.push({ fuzzer: 'Original*', 'domain-name': this.domain + '.' + this.tld });
    for (const domain of this.__addition()) {
      this.domains.push({ fuzzer: 'Addition', 'domain-name': `${domain}.${this.tld}` });
    }
    for (const domain of this.__bitsquatting()) {
      this.domains.push({ fuzzer: 'Bitsquatting', 'domain-name': `${domain}.${this.tld}` });
    }
    for (const domain of this.__homoglyph()) {
      this.domains.push({ fuzzer: 'Homoglyph', 'domain-name': `${domain}.${this.tld}` });
    }
    for (const domain of this.__hyphenation()) {
      this.domains.push({ fuzzer: 'Hyphenation', 'domain-name': `${domain}.${this.tld}` });
    }
    for (const domain of this.__insertion()) {
      this.domains.push({ fuzzer: 'Insertion', 'domain-name': `${domain}.${this.tld}` });
    }
    for (const domain of this.__omission()) {
      this.domains.push({ fuzzer: 'Omission', 'domain-name': `${domain}.${this.tld}` });
    }
    for (const domain of this.__repetition()) {
      this.domains.push({ fuzzer: 'Repetition', 'domain-name': `${domain}.${this.tld}` });
    }
    for (const domain of this.__replacement()) {
      this.domains.push({ fuzzer: 'Replacement', 'domain-name': `${domain}.${this.tld}` });
    }
    for (const domain of this.__subdomain()) {
      this.domains.push({ fuzzer: 'Subdomain', 'domain-name': `${domain}.${this.tld}` });
    }
    for (const domain of this.__transposition()) {
      this.domains.push({ fuzzer: 'Transposition', 'domain-name': `${domain}.${this.tld}` });
    }
    for (const domain of this.__vowel_swap()) {
      this.domains.push({ fuzzer: 'Vowel-swap', 'domain-name': `${domain}.${this.tld}` });
    }
    if (!this.domain.startsWith('www.')) {
      for (const domain of this.__various()) {
        this.domains.push({ fuzzer: 'Various', 'domain-name': `${domain}.${this.tld}` });
      }
    }
    if (this.tld.includes('.')) {
      this.domains.push({ fuzzer: 'Various', 'domain-name': `${this.domain}.${this.tld.split('.')[this.tld.split('.').length - 1]}` });
      this.domains.push({ fuzzer: 'Various', 'domain-name': this.domain + this.tld });
    } else {
      this.domains.push({ fuzzer: 'Various', 'domain-name': `${this.domain + this.tld}.${this.tld}` });
    }
    if (this.tld !== 'com' && !this.tld.includes('.')) {
      this.domains.push({ fuzzer: 'Various', 'domain-name': `${this.domain}-${this.tld}.com` });
    }

    this.__filter_domains();
  }
}

class DomainDict extends DomainFuzz {
  constructor(domain) {
    super(domain);
    this.dictionary = [];
  }
  load_dict(file) {
    if (fs.existsSync(file)) {
      const data = fs.readFileSync(file);
      for (let word of data.toString().split('\n')) {
        word = word.trim();
        if (word && !word.startsWith('//')) {
          this.dictionary.push(word);
        }
      }
    }
  }

  __dirtionary() {
    const result = [];
    const domain = rsplit(this.domain, '.', 1);
    let prefix;
    let name;
    if (domain.length > 1) {
      prefix = `${domain[0]}.`;
      name = domain[1];
    } else {
      prefix = '';
      name = domain[0];
    }
    for (const word of this.dictionary) {
      result.push(`${prefix + name}-${word}`);
      result.push(prefix + name + word);
      result.push(`${prefix + word}-${name}`);
      result.push(prefix + word + name);
    }
    return result;
  }

  generate() {
    for (const domain of this.__dirtionary()) {
      this.domains.push({ fuzzer: 'Dictionary', 'domain-name': `${domain}.${this.tld}` });
    }
  }
}

class DomainThread {
  constructor(domain) {
    this.domain = domain;
    this.ssdeep_orig = '';
    this.domain_orig = '';
    this.target = '';

    this.option_output = '';
    this.option_format = '';
    this.concurrency = 0;

    this.nameservers = false;
    this.option_geoip = false;
    this.option_whois = false;
    this.option_ssdeep = false;
    this.option_banners = false;
    this.option_mxcheck = false;
  }

  __banner_http(ip, vhost, callback) {
    const port = 80;
    const socket = net.createConnection({ port, host: ip });
    socket.write(`HEAD / HTTP/1.1\r\nHost: ${vhost}\r\nUser-agent: Mozilla/5.0\r\n\r\n`);
    let data = Buffer('');
    socket
      .setTimeout(CONF.REQUEST_BANNER_TIMEOUT)
      .on('data', (chunk) => {
        data = Buffer.concat([data, chunk]);
        socket.end();
      })
      .on('error', () => null)
      .on('end', () => {
        const response = data.toString('utf8');
        const sep = response.includes('\r\n') ? '\r\n' : '\n';
        const headers = response.split(sep);
        for (const field of headers) {
          if (field.startsWith('Server: ')) {
            return callback(null, field.substr(8));
          }
        }
        const banner = headers[0].split(' ');
        if (banner.length > 1) {
          return callback(null, `HTTP ${banner[1]}`);
        }
      });
  }

  __banner_smtp(ip, callback) {
    const port = 25;
    const socket = net.createConnection({ port, host: ip });
    let data = Buffer('');
    socket
      .setTimeout(CONF.REQUEST_BANNER_TIMEOUT)
      .on('data', (chunk) => {
        data = Buffer.concat([data, chunk]);
        socket.end();
      })
      .on('error', () => null)
      .on('end', () => {
        const response = data.toString('utf8');
        const sep = response.includes('\r\n') ? '\r\n' : '\n';
        const hello = response.split(sep)[0];
        if (hello.startsWith('220')) {
          return callback(null, hello.substr(4).trim());
        }
        return callback(null, hello.substr(0, 40));
      });
  }

  __mxcheck(mx, from_domain, to_domain, callback) {
    const from_addr = `randomgenius${Math.floor(Math.random() * 10)}@${from_domain}`;
    const to_addr = `randommaster${Math.floor(Math.random() * 10)}@${to_domain}`;
    const transportOptions = {
      host: mx,
      port: 25,
      greetingTimeout: CONF.REQUEST_BANNER_TIMEOUT,
      connectionTimeout: CONF.REQUEST_BANNER_TIMEOUT,
      socketTimeout: CONF.REQUEST_BANNER_TIMEOUT,
    };
    debug(`Transport Options: ${JSON.stringify(transportOptions)}`);
    const transporter = nodemailer.createTransport();
    const mailOptions = {
      from: from_addr,
      to: to_addr,
      text: `${CONF.name} MX Check.`,
    };
    transporter.sendMail(mailOptions, (err, info) => {
      debug(`Send Mail: ${err ? err.message : info.message + info.response}`);
      callback(!err);
    });
  }

  run(domain) {
    const domainName = url.domainToASCII(domain['domain-name']);
    const names = `${domainName}(${domain['domain-name']})`;
    if (domain['domain-name'] !== domainName) {
      domain['domain-name-ascii'] = domainName;
    }
    // Fetch NS Resolve
    if (this.nameservers && this.nameservers.length) {
      try {
        dns.setServers(this.nameservers);
      } catch (err) {
        printError('Set nameserver failed.');
      }
    }
    return new Promise((callback) => {
      new Promise((resolve) => {
        dns.resolve(domainName, 'NS', (err, res) => {
          if (err) {
            debug(`${names} DNS NS query NS error: ${res}`);
            return resolve(false);
          }
          debug(`${names} DNS NS query: ${res}`);
          resolve(res);
        });
      })
      .then((ns) => {
        if (ns) domain['dns-ns'] = ns;
        // resolve A
        new Promise((resolve, reject) => {
          dns.resolve(domainName, 'A', (err, res) => {
            if (err) return reject(err);
            debug(`${names} DNS A query: ${res}`);
            resolve(res);
          });
        })
        .then((resolveA) => {
          if (resolveA) domain['dns-a'] = resolveA;
          const fetchAAAA = new Promise((resolve, reject) => {
            dns.resolve(domainName, 'AAAA', (err, res) => {
              if (err) return reject(err);
              if (!res.length) return resolve(false);
              debug(`${names} DNS AAAA query: ${res}`);
              resolve(res);
            });
          });

          return fetchAAAA;
        })
        .then((resolveAAAA) => {
          if (resolveAAAA) domain['dns-aaaa'] = resolveAAAA;
          const fetchMX = new Promise((resolve, reject) => {
            dns.resolve(domainName, 'MX', (err, res) => {
              if (err) return reject(err);
              const resolves = res.map((_) => _.exchange);
              debug(`${names} DNS MX query: ${JSON.stringify(resolves)}`);
              resolve(resolves);
            });
          });
          return fetchMX;
        })
        .then((resolveMX) => {
          if (resolveMX) domain['dns-mx'] = resolveMX;
        })
        .catch((err) => {
          debug(`${names} DNS query error: ${err.message}`);
        });
      })
      .then(() => {
        const fetchWhois = new Promise((resolve) => {
          const isRegistered = !!(Reflect.has(domain, 'dns-ns') || !Reflect.has(domain, 'dns-a'))
          if (!isRegistered) {
            debug(`[WHOIS] ${domain['domain-name']}(${domainName}). Domain is not registered.`);
            resolve(false);
            return false;
          }
          libwhois(domainName, (err, res) => {
            if (err) {
              debug(`[WHOIS] ${domain['domain-name']}(${domainName}). Query error. ${err}`);
              resolve(false);
              return false;
            }
            const { creationDate, updatedDate } = res;
            debug(`[WHOIS] ${domain['domain-name']}(${domainName}) Whois query result: ${JSON.stringify({ creationDate, updatedDate })}`);
            return resolve({ creationDate, updatedDate });
          });
        });
        if (this.option_whois) {
          return fetchWhois;
        }
      })
      .then((whois) => {
        if (whois) {
          const { creationDate, updatedDate } = whois;
          if (creationDate) domain['whois-created'] = creationDate;
          if (updatedDate) domain['whois-updated'] = updatedDate;
        }
        const fetchGeoip = new Promise((resolve) => {
          const hasResolveA = Reflect.has(domain, 'dns-a');
          if (!hasResolveA) {
            debug(`[GEOIP2] ${domain['domain-name']}(${domainName}). Domain has not resolve A.`);
            resolve(false);
            return false;
          }
          geoip2.lookupSimple(domain['dns-a'][0], (err, res) => {
            if (err) {
              debug(`[GEOIP2] ${domain['domain-name']}(${domainName}). ${err.message}`);
              return resolve(false);
            }
            if (!res) {
              return resolve(false);
            }
            debug(`[GEOIP2] ${domain['domain-name']}(${domainName}). ${res.country}`);
            resolve(res.country);
          });
        });
        if (this.option_geoip) {
          return fetchGeoip;
        }
        return false;
      })
      .then((country) => {
        if (country) {
          domain['geoip-country'] = country;
        }
        const fetchBannerHTTP = new Promise((resolve) => {
          const hasResolveA = Reflect.has(domain, 'dns-a');
          if (!hasResolveA) {
            debug(`[BANNERS][HTTP] ${domain['domain-name']}(${domainName}). Domain has not resolve A.`);
            resolve(false);
            return false;
          }
          this.__banner_http(domain['dns-a'][0], domainName, (err, banner) => {
            if (err) {
              debug(`[BANNERS][HTTP] ${domain['domain-name']}(${domainName}). Fetch banner HTTP error: ${err}`);
              resolve(false);
              return false;
            }
            debug(`[BANNERS][HTTP] ${domain['domain-name']}(${domainName}): ${banner}`);
            resolve(banner);
          });
        });
        if (this.option_banners) {
          return fetchBannerHTTP;
        }
        return false;
      })
      .then((bannerHTTP) => {
        if (bannerHTTP) domain['banner-http'] = bannerHTTP;

        const fetchBannerSMTP = new Promise((resolve) => {
          const hasResolveMX = Reflect.has(domain, 'dns-mx');
          if (!hasResolveMX) {
            debug(`[BANNERS][SMTP] ${domain['domain-name']}(${domainName}). Domain has not resolve MX.`);
            resolve(false);
            return false;
          }
          this.__banner_smtp(domain['dns-mx'][0], (err, banner) => {
            if (err) {
              debug(`[BANNERS][SMTP] ${domain['domain-name']}(${domainName}).Fetch Banner SMTP Error: ${err}`);
              resolve(false);
            }
            debug(`[BANNERS][SMTP] ${domain['domain-name']}(${domainName}). Banner SMTP: ${banner}`);
            resolve(banner);
          });
        });

        if (this.option_banners) {
          return fetchBannerSMTP;
        }
        return false;
      })
      .then((bannerSMTP) => {
        if (bannerSMTP) domain['banner-smtp'] = bannerSMTP;

        const fetchSSDEEP = new Promise((resolve) => {
          const hasResolveA = Reflect.has(domain, 'dns-a');
          if (!hasResolveA) {
            debug(`[SSDEEP] ${domain['domain-name']}(${domainName}). Domain has not resolve A.`);
            resolve(false);
            return false;
          }
          const options = { url: this.target.href, method: 'GET', timeout: CONF.REQUEST_BANNER_TIMEOUT };
          const headers = { 'User-Agent': `Mozilla/5.0 ${CONF.name}/${CONF.version}` };
          options.headers = headers;
          debug(`[SSDEEP] ${domain['domain-name']}(${domainName}). Request Options: ${JSON.stringify(options)}`);
          request(options, (err, res, body) => {
            if (err) {
              resolve(false);
              return false;
            }
            if (res.statusCode === 200) {
              const ssdeep_fuzz = libssdeep.hash(body);
              const ssdeepScore = libssdeep.compare(this.ssdeep_orig, ssdeep_fuzz);
              debug(`SSDEEP Score: ${ssdeepScore}`);
              resolve(ssdeepScore);
            }
            resolve(false);
          });
        });

        if (this.option_ssdeep) {
          return fetchSSDEEP;
        }
      })
      .then((ssdeepScore) => {
        if (ssdeepScore) domain['ssdeep-score'] = ssdeepScore;
      })
      .then(() => {
        callback(domain);
      })
      .catch((err) => {
        printError(err);
      });
    });
  }
}

exports.DomainFuzz = DomainFuzz;
exports.DomainDict = DomainDict;
exports.DomainThread = DomainThread;
