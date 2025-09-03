// config/db.js
const { Pool } = require('pg');
const { Sequelize } = require('sequelize');

// Pull from env, fallback to defaults
const {
  DB_HOST = 'localhost',
  DB_PORT = '5432',
  DB_NAME = 'weeatdb',
  DB_USER = 'weeatuser',
  DB_PASS = 'mijungbeam211237',
} = process.env;

// pg pool for sessions / raw queries
const pgPool = new Pool({
  host: DB_HOST,
  port: Number(DB_PORT),
  database: DB_NAME,
  user: DB_USER,
  password: DB_PASS,
});

// sequelize for ORM models
const sequelize = new Sequelize(DB_NAME, DB_USER, DB_PASS, {
  host: DB_HOST,
  port: Number(DB_PORT),
  dialect: 'postgres',
  logging: false, // keep console clean
});

module.exports = { sequelize, pgPool };
