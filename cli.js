#!/usr/bin/env node
const fs = require('fs');
const debug = require('debug')('fuzz:main');
const Promise = require('bluebird');
const program = require('commander');
const request = require('request');
const libssdeep = require('ssdeep');
const csv = require('csv');
const ProgressBar = require('progress');
const CONF = require('./config');
const { printError, printInfo, printResult, printBanner, parseTarget, bye } = require('./lib/utils');
const { DomainFuzz, DomainDict, DomainThread } = require('./lib');

const fuzz = (opts, domains, worker) => {
  const total = domains.length;
  const bar = new ProgressBar('Running [:bar] :percent :etas', {
    complete: '=',
    incomplete: ' ',
    width: 50,
    total,
  });
  Promise
    .map(domains, (domain) => {
      bar.tick(1);
      return worker.run(domain);
    }, { concurrency: opts.concurrency })
    .then((result) => {
      if (opts.option_output) {
        let data;
        if (opts.option_format === 'JSON') {
          data = JSON.stringify(result, null, 4);
          fs.appendFile(opts.option_output, data, 'utf8', (err) => {
            if (err) printError(err.message);
          });
        } else if (opts.option_format === 'CSV') {
          data = [];
          const columns = 'fuzzer,domain-name,dns-a,dns-aaaa,dns-mx,dns-ns,geoip-country,whois-created,whois-updated,ssdeep-score';
          data.push(columns.split(','));
          for (const domain of result) {
            data.push(columns.split(',').map(_ => domain[_]));
          }
          csv.stringify(data, (parseErr, res) => {
            fs.appendFile(this.option_output, res, 'utf8', (err) => {
              if (err) printError(err.message);
            });
          });
        }
      }
      for (const domain of result) {
        printResult(domain);
      }
    })
    .catch(err => printError(err.message));
};

const main = () => {
  const opts = program
    .version(CONF.version)
    .usage('[options] DOMAIN')
    .description(`Find similar-looking domain names that adversaries can use to attack you. Can
detect typosquatters, phishing attacks, fraud and corporate espionage. Useful
as an additional source of targeted threat intelligence.`)
    .option('--target <domain>', 'target domain name or URL to check', parseTarget)
    .option('-o --out-put <file>', 'Output filename')
    .option('-f --format <type>', 'Output format (JSON|CSV) [JSON]', val => val.toUpperCase(), 'JSON')
    .option('-c --concurrency <num>', 'start specified NUMBER of concurrency', Math.abs, CONF.CONCURRENCY_COUNT_DEFAULT)
    .option('--modules <module>', 'Enable modules (whois|banners|mxcheck|ssdeep|geoip)', val => val.split(/\W/), [])
    .option('--nameservers <nameservers>', 'comma separated list of nameservers to query', val => val.split(','))
    .option('--dictionary <file>', 'generate additional domains using dictionary FILE')
    .option('--registered', 'show only registered domain names (TODO)')// TODO.
    .option('--can-register', 'show only can register domain names (TODO)')// TODO.
    .parse(process.argv);

  if (!process.argv.slice(2).length) {
    printInfo(`  ${CONF.name} ${CONF.version} by ${CONF.author}`);
    opts.outputHelp();
    bye(0);
  }

  if (!opts.target) {
    printError('The target is required');
    bye(-1);
  }

  if (opts.format) {
    if (!['JSON', 'CSV'].includes(opts.format)) {
      printError('Format must be JSON or CSV');
      bye(-1);
    }
  }

  if (opts.concurrency < 1) {
    opts.concurrency = CONF.CONCURRENCY_COUNT_DEFAULT;
  }

  printBanner();

  const domainFuzz = new DomainFuzz(opts.target.host);
  domainFuzz.generate();
  let { domains } = domainFuzz;

  if (opts.dictionary) {
    if (!fs.existsSync(opts.dictionary)) {
      printError(`dictionary not found: ${opts.dictionary}`);
      return false;
    }

    const domainDict = new DomainDict(opts.target.host);
    domainDict.load_dict(opts.dictionary);
    domainDict.generate();
    domains = domains.concat(domainDict.domains);
  }

  debug(`Domains: ${JSON.stringify(domains)}`);
  printInfo(`Processing ${domains.length} domain variants`);
  printInfo(`Enable modules: ${opts.modules.length ? opts.modules.join(', ') : '-'}`);

  const worker = new DomainThread(domains);

  // Modules
  if (opts.modules) {
    const modules = opts.modules;
    if (modules.includes('whois')) worker.option_whois = true;
    if (modules.includes('banners')) worker.option_banners = true;
    if (modules.includes('ssdeep')) worker.option_ssdeep = true;
    if (modules.includes('mxcheck')) worker.option_mxcheck = true;
    if (modules.includes('geoip')) worker.option_geoip = true;
  }

  worker.target = opts.target;
  worker.option_output = opts.outPut;
  worker.option_format = opts.format;
  worker.concurrency = opts.concurrency;
  worker.nameservers = opts.nameservers;

  // console.log(opts.modules, opts.modules.includes('ssdeep'))
  if (opts.modules && opts.modules.includes('ssdeep')) {
    printInfo(`Fetching content from: ${opts.target.href} ...`);
    const options = { url: opts.target.href, method: 'GET', timeout: CONF.REQUEST_BANNER_TIMEOUT };
    const headers = { 'User-Agent': `Mozilla/5.0 ${CONF.name}/${CONF.version}` };
    options.headers = headers;
    debug(`request: ${JSON.stringify(options)}`);
    return new Promise((resolve) => {
      request(options, (err, res, body) => {
        if (err) {
          printError(`fetch ssdeep orig failed. ${err.message}`);
          return resolve(false);
        }
        printInfo(`${res.statusCode} ${res.statusMessage} (${body.length / 1000} Kbytes)`);
        if (res.statusCode === 200) {
          const ssdeep_orig = libssdeep.hash(body);
          debug(`ssdeep_orig: ${ssdeep_orig}`);
          return resolve(ssdeep_orig);
        }
        return resolve(false);
      });
    })
    .then((ssdeep_orig) => {
      if (ssdeep_orig) {
        worker.ssdeep_orig = ssdeep_orig;
      }
      fuzz(opts, domains, worker);
    });
  }

  fuzz(opts, domains, worker);
};

if (require.main) main();
