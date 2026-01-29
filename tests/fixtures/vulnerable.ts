// Test fixture: vulnerable TypeScript file with various security issues
// This file is intentionally insecure for testing purposes

import { exec } from 'child_process';
import * as fs from 'fs';
import * as crypto from 'crypto';

// CRITICAL: Hardcoded API key
const apiKey = "secret_test_abcdef1234567890abcdef1234567890";

// CRITICAL: Hardcoded password
const password = "SuperSecret123!";

// HIGH: SQL injection via template literal
function getUser(userId: string) {
  const db = { query: (q: string) => q };
  return db.query(`SELECT * FROM users WHERE id = ${userId}`);
}

// HIGH: XSS via innerHTML
function renderComment(comment: string) {
  const el = document.createElement('div');
  el.innerHTML = comment;
  return el;
}

// HIGH: Command injection
function convertFile(filename: string) {
  exec(`convert ${filename}.png output.jpg`);
}

// HIGH: eval usage
function runCode(code: unknown) {
  eval(code as string);
}

// HIGH: Path traversal
function readUserFile(req: { params: { filename: string } }) {
  const file = fs.readFile(req.params.filename, 'utf-8', () => {});
}

// MEDIUM: Weak crypto MD5
function hashData(data: string) {
  return crypto.createHash("md5").update(data).digest("hex");
}

// MEDIUM: Insecure cookie
function setCookie(res: { cookie: Function }) {
  res.cookie("session", "abc123");
}

// MEDIUM: CORS wildcard
function setupCors(app: { use: Function }) {
  app.use(cors());
}

// MEDIUM: Console log sensitive data
function debugAuth(token: string) {
  console.log("Auth token:", token);
}

// LOW: Debug mode
const DEBUG = true;

// LOW: HTTP URL
const apiUrl = "http://api.example.com/data";

// LOW: Security TODO
// TODO: fix authentication bypass vulnerability

function cors() { return () => {} }
