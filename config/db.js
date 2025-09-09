const { Pool } = require('pg');
const { Sequelize } = require('sequelize');

const {
  DB_HOST = 'localhost',
  DB_PORT = '5432',
  DB_NAME = 'weeatdb',
  DB_USER = 'weeatuser',
  DB_PASS = '',
  DB_SSL = 'false'
} = process.env;

const pgPool = new Pool({
  host: DB_HOST,
  port: Number(DB_PORT),
  database: DB_NAME,
  user: DB_USER,
  password: DB_PASS,
  ssl: DB_SSL === 'true' ? { rejectUnauthorized: false } : false
});

const sequelize = new Sequelize(DB_NAME, DB_USER, DB_PASS, {
  host: DB_HOST,
  port: Number(DB_PORT),
  dialect: 'postgres',
  logging: false,
  dialectOptions: DB_SSL === 'true' ? { ssl: { rejectUnauthorized: false } } : {}
});

module.exports = { sequelize, pgPool };
