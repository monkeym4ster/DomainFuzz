const path = require('path');
const PKG = require('./package');

const config = {};
config.name = PKG.name;
config.version = PKG.version;
config.author = PKG.author;
config.BASE_DIR = path.resolve(__dirname);
config.DB_DIR = path.join(config.BASE_DIR, 'database');
config.LIB_DIR = path.join(config.BASE_DIR, 'lib');
config.TLD_FILE = path.join(config.DB_DIR, 'effective_tld_names.dat');
config.GEOIP_FILE = path.join(config.DB_DIR, 'GeoLite2-Country.mmdb');
config.banner = path.join(config.LIB_DIR, 'banner.txt');

config.REQUEST_BANNER_TIMEOUT = 2000;
config.CONCURRENCY_COUNT_DEFAULT = 10;

module.exports = config;
