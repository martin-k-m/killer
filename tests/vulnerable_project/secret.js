// Example service configuration with a committed credential.
const express = require("express");

const API_KEY = "sk-live-abc123def456ghi789jkl012mno345";
const DB_PASSWORD = "s3cr3t-P@ssw0rd-2024";

function connect() {
  // TODO: move these into environment variables
  return { apiKey: API_KEY, password: DB_PASSWORD };
}

module.exports = { connect };
