const fs = require('fs');
const url = require('url');
const _ = require('lodash');
const chalk = require('chalk');
const CONF = require('../config');

exports.rsplit = (str, sep, maxsplit) => {
  const split = str.split(sep);
  if (split.length > maxsplit) {
    return maxsplit ? [split.slice(0, -maxsplit).join(sep)].concat(split.slice(-maxsplit)) : split;
  }
  return split;
};

exports.printError = (data) => {
  console.error(chalk.red(`Error: ${data}`));
};

exports.printInfo = (data) => {
  console.log(chalk.bold(data));
};

exports.parseTarget = (target) => {
  let targetCopy = url.parse(target);
  if (!targetCopy.protocol) {
    targetCopy = url.parse(`http://${target}`);
  }
  return targetCopy;
};

exports.bye = (code) => {
  process.exit(code);
};

exports.printBanner = () => {
  const data = fs.readFileSync(CONF.banner);
  const content = data.toString('utf8');
  const sep = '\n'.repeat(6);
  const banners = content.split(sep);
  let banner = _.sample(banners);
  const version = `{${CONF.version}}`;
  const prefix = banner.substr(0, banner.length - version.length - 1);
  const append = banner.substr(banner.length - 1, 1);
  banner = prefix;
  banner += `${chalk.bold(version)}${append}\n\n`;
  const colors = [chalk.green, chalk.cyan, chalk.magenta, chalk.yellow];
  const color = _.sample(colors);
  console.log(color(banner));
};

exports.printResult = (domain) => {
  const line = [];
  line.push(chalk.blue(domain['domain-name']));
  if (Reflect.has(domain, 'dns-a')) {
    line.push(`${chalk.yellow('A')}: ${domain['dns-a']}`);
    if (Reflect.has(domain, 'geoip-country')) {
      line.push(`(${domain['geoip-country']})`);
    }
  }
  if (Reflect.has(domain, 'dns-aaaa')) {
    line.push(`${chalk.yellow('AAAA')}: ${domain['dns-aaaa']}`);
  }
  if (Reflect.has(domain, 'dns-ns')) {
    line.push(`${chalk.yellow('NS')}: ${domain['dns-ns']}`);
  }
  if (Reflect.has(domain, 'dns-mx')) {
    line.push(`${chalk.yellow('MX')}: ${domain['dns-mx']}`);
  }
  if (Reflect.has(domain, 'banner-http')) {
    line.push(`${chalk.yellow('HTTP')}: ${domain['banner-http']}`);
  }
  if (Reflect.has(domain, 'banner-smtp')) {
    line.push(`${chalk.yellow('SMTP')}: ${domain['banner-smtp']}`);
  }
  if (Reflect.has(domain, 'whois-created')) {
    line.push(`${chalk.yellow('WHOIS')}: ${domain['whois-created']}`);
    if (Reflect.has(domain, 'whois-updated')) {
      line.push(`${domain['whois-updated']}`);
    }
  }
  if (Reflect.has(domain, 'ssdeep-score')) {
    line.push(`${chalk.yellow('SSDEEP')}: ${domain['ssdeep-score']}`);
  }
  // console.log(line);
  if (line.length < 2) line.push('-');
  console.log(line.join(' '));
};
