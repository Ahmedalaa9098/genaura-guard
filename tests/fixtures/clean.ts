// Test fixture: clean TypeScript file with no security issues

import * as crypto from 'crypto';

// Proper env var usage
const apiKey = process.env.API_KEY;

// Parameterized query
function getUser(db: { query: Function }, userId: string) {
  return db.query("SELECT * FROM users WHERE id = ?", [userId]);
}

// Safe text content
function renderComment(el: Element, comment: string) {
  el.textContent = comment;
}

// Proper hashing
function hashPassword(password: string) {
  return crypto.createHash("sha256").update(password).digest("hex");
}

// HTTPS URL
const apiUrl = "https://api.example.com/data";

// Secure cookie
function setCookie(res: { cookie: Function }) {
  res.cookie("session", "value", {
    httpOnly: true,
    secure: true,
    sameSite: "strict",
  });
}
