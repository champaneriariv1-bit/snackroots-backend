const crypto = require("crypto");
const fs = require("fs");
const path = require("path");
const express = require("express");
const { DatabaseSync } = require("node:sqlite");
require("dotenv").config();

const app = express();
const PORT = Number(process.env.PORT || 3000);
const DATA_DIR = path.join(__dirname, "data");
const ORDERS_FILE = path.join(DATA_DIR, "orders.json");
const DONATIONS_FILE = path.join(DATA_DIR, "donations.json");
const SQLITE_FILE = path.join(DATA_DIR, "snackroots.sqlite");
const MAX_ORDER_ITEMS = 30;
const rateBuckets = new Map();
let db;
const ADMIN_KEYS = String(process.env.ADMIN_KEYS || "")
  .split(",")
  .map((key) => key.trim())
  .filter(Boolean);
const ALLOWED_ORIGINS = String(process.env.ALLOWED_ORIGINS || "")
  .split(",")
  .map((origin) => origin.trim().replace(/\/+$/, ""))
  .filter(Boolean);

function originAllowed(origin) {
  if (!origin) return true;
  const normalized = String(origin).replace(/\/+$/, "");
  if (ALLOWED_ORIGINS.includes("*")) return true;
  if (ALLOWED_ORIGINS.includes(normalized)) return true;
  return /^https:\/\/[a-z0-9-]+--[a-z0-9-]+\.netlify\.app$/i.test(normalized) &&
    ALLOWED_ORIGINS.some((item) => /^https:\/\/[a-z0-9-]+\.netlify\.app$/i.test(item));
}

function ensureStore() {
  fs.mkdirSync(DATA_DIR, { recursive: true });
  if (!db) {
    db = new DatabaseSync(SQLITE_FILE);
    db.exec(`
      CREATE TABLE IF NOT EXISTS orders (
        id TEXT PRIMARY KEY,
        status TEXT NOT NULL,
        total_amount INTEGER NOT NULL DEFAULT 0,
        donation_amount INTEGER NOT NULL DEFAULT 0,
        created_at TEXT NOT NULL,
        updated_at TEXT,
        payload TEXT NOT NULL
      );
      CREATE TABLE IF NOT EXISTS donations (
        id TEXT PRIMARY KEY,
        order_id TEXT,
        status TEXT NOT NULL,
        amount INTEGER NOT NULL DEFAULT 0,
        created_at TEXT NOT NULL,
        updated_at TEXT,
        payload TEXT NOT NULL
      );
      CREATE INDEX IF NOT EXISTS idx_orders_created_at ON orders(created_at);
      CREATE INDEX IF NOT EXISTS idx_orders_status ON orders(status);
      CREATE INDEX IF NOT EXISTS idx_donations_order_id ON donations(order_id);
    `);
    migrateJsonFile(ORDERS_FILE, "orders");
    migrateJsonFile(DONATIONS_FILE, "donations");
  }
}

function migrateJsonFile(file, table) {
  if (!fs.existsSync(file)) return;
  const count = db.prepare(`SELECT COUNT(*) AS count FROM ${table}`).get().count;
  if (count > 0) return;
  let rows = [];
  try {
    rows = JSON.parse(fs.readFileSync(file, "utf8"));
  } catch {
    rows = [];
  }
  if (!Array.isArray(rows) || rows.length === 0) return;
  writeRows(table, rows);
}

function rowToObject(row) {
  if (!row) return null;
  try {
    return JSON.parse(row.payload);
  } catch {
    return null;
  }
}

function readRows(table) {
  ensureStore();
  const rows = db
    .prepare(`SELECT payload FROM ${table} ORDER BY created_at DESC`)
    .all();
  return rows.map(rowToObject).filter(Boolean);
}

function writeRows(table, values) {
  ensureStore();
  const rows = Array.isArray(values) ? values : [];
  const insertOrder = db.prepare(`
    INSERT OR REPLACE INTO orders
      (id, status, total_amount, donation_amount, created_at, updated_at, payload)
    VALUES (?, ?, ?, ?, ?, ?, ?)
  `);
  const insertDonation = db.prepare(`
    INSERT OR REPLACE INTO donations
      (id, order_id, status, amount, created_at, updated_at, payload)
    VALUES (?, ?, ?, ?, ?, ?, ?)
  `);
  const tx = db.transaction(() => {
    db.exec(`DELETE FROM ${table}`);
    for (const value of rows) {
      if (!value || !value.id) continue;
      if (table === "orders") {
        insertOrder.run(
          value.id,
          cleanText(value.status, 40) || "pending",
          rupees(value.totalAmount),
          rupees(value.donationAmount),
          value.createdAt || new Date().toISOString(),
          value.updatedAt || null,
          JSON.stringify(value)
        );
      } else {
        insertDonation.run(
          value.id,
          value.orderId || "",
          cleanText(value.status, 80) || "pending",
          rupees(value.amount),
          value.createdAt || new Date().toISOString(),
          value.updatedAt || null,
          JSON.stringify(value)
        );
      }
    }
  });
  tx();
}

function readJson(file) {
  if (file === ORDERS_FILE) return readRows("orders");
  if (file === DONATIONS_FILE) return readRows("donations");
  ensureStore();
  return fs.existsSync(file) ? JSON.parse(fs.readFileSync(file, "utf8")) : [];
}

function writeJson(file, value) {
  if (file === ORDERS_FILE) {
    writeRows("orders", value);
    return;
  }
  if (file === DONATIONS_FILE) {
    writeRows("donations", value);
    return;
  }
  ensureStore();
  fs.writeFileSync(file, `${JSON.stringify(value, null, 2)}\n`, "utf8");
}

function rawBodySaver(req, res, buf) {
  if (buf && buf.length) req.rawBody = buf.toString("utf8");
}

function securityHeaders(req, res, next) {
  const origin = req.get("origin");
  if (origin && originAllowed(origin)) {
    res.setHeader("Access-Control-Allow-Origin", origin);
    res.setHeader("Vary", "Origin");
    res.setHeader("Access-Control-Allow-Credentials", "false");
    res.setHeader("Access-Control-Allow-Headers", "Content-Type, X-Admin-Key");
    res.setHeader("Access-Control-Allow-Methods", "GET, POST, PATCH, OPTIONS");
  }
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("X-Frame-Options", "SAMEORIGIN");
  res.setHeader("Referrer-Policy", "strict-origin-when-cross-origin");
  res.setHeader("Permissions-Policy", "camera=(), microphone=(), geolocation=()");
  res.setHeader(
    "Content-Security-Policy",
    [
      "default-src 'self'",
      "script-src 'self' 'unsafe-inline' https://checkout.razorpay.com https://unpkg.com",
      "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com",
      "font-src 'self' https://fonts.gstatic.com",
      "img-src 'self' data: https:",
      "connect-src 'self' https://world.openfoodfacts.org https://*.openfoodfacts.org https://api.postalpincode.in https://checkout.razorpay.com https://api.razorpay.com",
      "frame-src 'self' about: data: https://api.razorpay.com https://checkout.razorpay.com",
      "base-uri 'self'",
      "form-action 'self'",
    ].join("; ")
  );
  next();
}

function rateLimit(name, limit, windowMs) {
  return (req, res, next) => {
    const ip = req.ip || req.socket.remoteAddress || "local";
    const key = `${name}:${ip}`;
    const now = Date.now();
    const bucket = rateBuckets.get(key) || { count: 0, resetAt: now + windowMs };
    if (now > bucket.resetAt) {
      bucket.count = 0;
      bucket.resetAt = now + windowMs;
    }
    bucket.count += 1;
    rateBuckets.set(key, bucket);
    res.setHeader("RateLimit-Limit", String(limit));
    res.setHeader("RateLimit-Remaining", String(Math.max(0, limit - bucket.count)));
    if (bucket.count > limit) {
      res.status(429).json({ error: "Too many requests. Please try again shortly." });
      return;
    }
    next();
  };
}

app.disable("x-powered-by");
app.use(securityHeaders);
app.options("*", (req, res) => {
  if (originAllowed(req.get("origin"))) {
    res.sendStatus(204);
    return;
  }
  res.status(403).json({ error: "Origin not allowed." });
});
app.use(express.json({ verify: rawBodySaver, limit: "120kb" }));
app.use((req, res, next) => {
  const requestedPath = decodeURIComponent(req.path || "");
  if (
    requestedPath.startsWith("/data/") ||
    requestedPath === "/.env" ||
    requestedPath === "/server.js" ||
    requestedPath === "/package-lock.json" ||
    requestedPath === "/package.json" ||
    requestedPath.endsWith(".json") && requestedPath !== "/manifest.json"
  ) {
    res.status(404).send("Not found");
    return;
  }
  next();
});
app.use(express.static(__dirname, {
  dotfiles: "deny",
  etag: true,
  index: false,
  maxAge: "1h",
  setHeaders(res, filePath) {
    if (filePath.endsWith(".html")) res.setHeader("Cache-Control", "no-store");
  },
}));

function adminKeysConfigured() {
  return ADMIN_KEYS.length > 0;
}

function getAdminKey(req) {
  return String(req.get("x-admin-key") || "").trim();
}

function requireAdmin(req, res, next) {
  if (!adminKeysConfigured()) {
    res.status(503).json({
      error: "Dashboard admin keys are not configured on the server.",
    });
    return;
  }
  if (!ADMIN_KEYS.includes(getAdminKey(req))) {
    res.status(401).json({ error: "Admin key required." });
    return;
  }
  next();
}

function rupees(value) {
  const amount = Number(value);
  return Number.isFinite(amount) ? Math.max(0, Math.round(amount)) : 0;
}

function cleanText(value, max = 200) {
  return String(value || "").replace(/\s+/g, " ").trim().slice(0, max);
}

function makeId(prefix) {
  return `${prefix}_${Date.now()}_${crypto.randomBytes(4).toString("hex")}`;
}

function validateOrderPayload(body) {
  const items = Array.isArray(body.items) ? body.items.slice(0, MAX_ORDER_ITEMS) : [];
  if (!cleanText(body.customerName, 120)) return "Customer name is required.";
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(cleanText(body.customerEmail, 160))) {
    return "A valid customer email is required.";
  }
  if (!cleanText(body.customerPhone, 40)) return "Customer phone is required.";
  if (!cleanText(body.deliveryAddress, 300)) return "Delivery address is required.";
  if (!/^\d{6}$/.test(cleanText(body.deliveryPincode, 12))) return "A valid delivery PIN code is required.";
  if (!items.length) return "At least one order item is required.";
  if (rupees(body.totalAmount) <= 0) return "Order total must be greater than zero.";
  return "";
}

function normalizeOrderPayload(body) {
  return {
    customerName: cleanText(body.customerName, 120),
    customerEmail: cleanText(body.customerEmail, 160),
    customerPhone: cleanText(body.customerPhone, 40),
    deliveryAddress: cleanText(body.deliveryAddress, 300),
    deliveryPincode: cleanText(body.deliveryPincode, 12),
    deliveryLocation: cleanText(body.deliveryLocation, 160),
    items: (Array.isArray(body.items) ? body.items : []).slice(0, MAX_ORDER_ITEMS).map((item) => ({
      id: cleanText(item.id, 80),
      name: cleanText(item.name, 120),
      icon: cleanText(item.icon, 12),
      price: rupees(item.price),
      qty: Math.min(99, Math.max(1, rupees(item.qty || 1))),
      type: cleanText(item.type, 40),
    })),
    subtotalAmount: rupees(body.subtotalAmount),
    discountAmount: rupees(body.discountAmount),
    couponCode: cleanText(body.couponCode, 40).toUpperCase(),
    couponStatus: cleanText(body.couponStatus, 40),
    totalAmount: rupees(body.totalAmount),
    eta: cleanText(body.eta, 160),
    donationPartner: "World Wildlife Fund",
    donationPercent: 2,
    donationAmount: rupees(body.donationAmount),
    donationStatus: cleanText(body.donationStatus, 60) || "pending_server_donation",
    paymentId: cleanText(body.paymentId, 120),
    status: cleanText(body.status, 40) || "confirmed",
  };
}

async function verifyRazorpayPayment(paymentId, expectedAmountRupees) {
  if (process.env.RAZORPAY_VERIFY_PAYMENTS !== "true") {
    return { verified: true, skipped: true };
  }
  if (!process.env.RAZORPAY_KEY_ID || !process.env.RAZORPAY_KEY_SECRET) {
    return {
      verified: false,
      status: 503,
      error: "Razorpay verification is enabled but server keys are not configured.",
    };
  }
  const id = cleanText(paymentId, 120);
  if (!/^pay_[A-Za-z0-9]+$/.test(id)) {
    return { verified: false, status: 400, error: "Invalid Razorpay payment ID." };
  }

  const auth = Buffer.from(
    `${process.env.RAZORPAY_KEY_ID}:${process.env.RAZORPAY_KEY_SECRET}`
  ).toString("base64");
  const response = await fetch(`https://api.razorpay.com/v1/payments/${id}`, {
    headers: { Authorization: `Basic ${auth}` },
  });
  const payment = await response.json().catch(() => ({}));
  if (!response.ok) {
    return {
      verified: false,
      status: 502,
      error: "Could not verify Razorpay payment.",
    };
  }

  const expectedPaise = rupees(expectedAmountRupees) * 100;
  const actualPaise = rupees(payment.amount);
  const captured = payment.status === "captured";
  if (!captured || actualPaise < expectedPaise || payment.currency !== "INR") {
    return {
      verified: false,
      status: 402,
      error: "Razorpay payment was not captured for the expected INR amount.",
    };
  }
  return { verified: true, providerPayment: payment };
}

function setupStatus() {
  return {
    storage: {
      type: "sqlite",
      ready: Boolean(db || fs.existsSync(SQLITE_FILE)),
    },
    razorpay: {
      verificationEnabled: process.env.RAZORPAY_VERIFY_PAYMENTS === "true",
      keyIdConfigured: Boolean(process.env.RAZORPAY_KEY_ID),
      keySecretConfigured: Boolean(process.env.RAZORPAY_KEY_SECRET),
      webhookSecretConfigured: Boolean(process.env.RAZORPAY_WEBHOOK_SECRET),
    },
    wwf: {
      donationsEnabled: process.env.WWF_DONATIONS_ENABLED === "true",
      rapidApiKeyConfigured: Boolean(process.env.WWF_RAPIDAPI_KEY),
      hostConfigured: Boolean(process.env.WWF_RAPIDAPI_HOST),
      endpointConfigured: Boolean(process.env.WWF_DONATION_ENDPOINT),
      ready: donationConfigReady(),
    },
  };
}

function csvCell(value) {
  return `"${String(value == null ? "" : value).replace(/"/g, '""')}"`;
}

function ordersToCsv(orders) {
  const headers = [
    "Order ID",
    "Customer",
    "Email",
    "Phone",
    "PIN",
    "Delivery Location",
    "ETA",
    "Address",
    "Items",
    "Total",
    "Payment ID",
    "Order Status",
    "WWF Amount",
    "WWF Status",
    "Created At",
  ];
  const lines = [headers.map(csvCell).join(",")];
  for (const order of orders) {
    const items = Array.isArray(order.items)
      ? order.items
          .map((item) => `${item.name || "Item"} x${item.qty || 1}`)
          .join("; ")
      : "";
    lines.push(
      [
        order.id,
        order.customerName,
        order.customerEmail,
        order.customerPhone,
        order.deliveryPincode,
        order.deliveryLocation,
        order.eta,
        order.deliveryAddress,
        items,
        order.totalAmount,
        order.paymentId,
        order.status,
        order.donationAmount,
        order.donationStatus,
        order.createdAt,
      ]
        .map(csvCell)
        .join(",")
    );
  }
  return `${lines.join("\n")}\n`;
}

const snackCatalog = [
  { id: "matcha-almonds", name: "Matcha Almonds", icon: "🍵", price: 189, weight: "60g", tags: ["calm", "antioxidant", "nutty", "protein", "japan"], reason: "calm crunch with almonds and matcha" },
  { id: "olive-crackers", name: "Olive Oil Crackers", icon: "🫒", price: 169, weight: "75g", tags: ["crunchy", "savory", "rosemary", "movie", "greece"], reason: "stone-baked crunch with olive oil and rosemary" },
  { id: "roasted-seaweed", name: "Roasted Seaweed", icon: "🌿", price: 139, weight: "25g", tags: ["light", "low calorie", "salty", "korea", "study"], reason: "light, salty, mineral-rich seaweed sheets" },
  { id: "pistachio-date", name: "Pistachio & Date Mix", icon: "🥜", price: 229, weight: "85g", tags: ["protein", "sweet", "energy", "nuts", "turkey"], reason: "pistachios plus dates for sweet energy" },
  { id: "cacao-quinoa", name: "Cacao Nibs & Quinoa", icon: "🌰", price: 199, weight: "70g", tags: ["protein", "sweet", "chocolate", "study", "peru"], reason: "protein-rich quinoa with cacao crunch" },
  { id: "zaatar-chickpeas", name: "Za'atar Chickpeas", icon: "🧄", price: 159, weight: "80g", tags: ["protein", "savory", "crunchy", "chickpea", "israel"], reason: "roasted chickpeas bring high-protein crunch" },
  { id: "dark-choc", name: "Dark Choc & Hazelnuts", icon: "🍫", price: 249, weight: "65g", tags: ["sweet", "chocolate", "nuts", "dessert", "italy"], reason: "dark chocolate and hazelnuts for a rich treat" },
  { id: "argan-crackers", name: "Argan Oil Crackers", icon: "🌶️", price: 179, weight: "75g", tags: ["savory", "crunchy", "cumin", "morocco"], reason: "warm cumin crackers with a nutty finish" },
  { id: "wasabi-peas", name: "Wasabi Pea Crunchies", icon: "🥒", price: 149, weight: "65g", tags: ["spicy", "protein", "crunchy", "peas", "japan"], reason: "spicy peas with bold protein-friendly crunch" },
  { id: "chilli-mango", name: "Chilli-Mango Bites", icon: "🥭", price: 219, weight: "70g", tags: ["spicy", "sweet", "fruit", "mexico"], reason: "sweet mango with chilli-lime heat" },
  { id: "truffle-popcorn", name: "Truffle Parm Popcorn", icon: "🍿", price: 259, weight: "55g", tags: ["crunchy", "movie", "savory", "cheese", "france"], reason: "movie-night popcorn with fancy truffle energy" },
  { id: "sour-cherry", name: "Sour Cherry Bombs", icon: "🍒", price: 199, weight: "45g", tags: ["sweet", "low sugar", "fruit", "tart", "hungary"], reason: "tart fruit with no added sugar vibes" },
  { id: "lavender-cookies", name: "Lavender Honey Cookies", icon: "🍯", price: 219, weight: "80g", tags: ["sweet", "cookies", "tea", "dessert", "france"], reason: "soft floral sweetness for tea-time cravings" },
  { id: "pickle-crisps", name: "Pickle Power Crisps", icon: "🧀", price: 169, weight: "70g", tags: ["crunchy", "salty", "tangy", "movie", "usa"], reason: "tangy cassava crisps for loud crunch cravings" },
  { id: "harissa-almonds", name: "Harissa Almonds", icon: "🌶️", price: 209, weight: "65g", tags: ["spicy", "protein", "almonds", "nuts", "tunisia"], reason: "smoky harissa almonds with lingering heat" },
];

function scoreSnack(query, snack) {
  const q = String(query || "").toLowerCase();
  let score = 0;
  for (const tag of snack.tags) {
    if (q.includes(tag)) score += 4;
  }
  if (q.includes("high protein") && snack.tags.includes("protein")) score += 6;
  if (q.includes("spicy") && snack.tags.includes("spicy")) score += 6;
  if (q.includes("sweet") && snack.tags.includes("sweet")) score += 5;
  if (q.includes("crunch") && snack.tags.includes("crunchy")) score += 5;
  if (q.includes("movie") && snack.tags.includes("movie")) score += 5;
  if (q.includes("study") && snack.tags.includes("study")) score += 5;
  if (q.includes("low sugar") && snack.tags.includes("low sugar")) score += 7;
  return score;
}

function matchesCustomAvoids(query, snack) {
  const q = String(query || "").toLowerCase();
  const name = snack.name.toLowerCase();
  if (
    (q.includes("no nuts") ||
      q.includes("nut free") ||
      q.includes("nut-free") ||
      q.includes("without nuts")) &&
    (snack.tags.includes("nuts") ||
      snack.tags.includes("almonds") ||
      name.includes("almond") ||
      name.includes("hazelnut") ||
      name.includes("pistachio"))
  ) {
    return false;
  }
  if (
    (q.includes("no chocolate") || q.includes("without chocolate")) &&
    snack.tags.includes("chocolate")
  ) {
    return false;
  }
  if (
    (q.includes("no spicy") ||
      q.includes("not spicy") ||
      q.includes("without spice")) &&
    snack.tags.includes("spicy")
  ) {
    return false;
  }
  return true;
}

function recommendSnacks(query) {
  const search = query || "spicy high-protein snacks";
  const filtered = snackCatalog.filter((snack) => matchesCustomAvoids(search, snack));
  return (filtered.length ? filtered : snackCatalog)
    .map((snack) => ({
      ...snack,
      matchScore: Math.max(62, scoreSnack(search, snack)),
      matchReason: snack.reason,
    }))
    .sort((a, b) => b.matchScore - a.matchScore || a.price - b.price)
    .slice(0, 3);
}

function calculateDonationAmount(order) {
  return Math.round(rupees(order.totalAmount) * 0.02);
}

function donationConfigReady() {
  return Boolean(
    process.env.WWF_DONATIONS_ENABLED === "true" &&
      process.env.WWF_RAPIDAPI_KEY &&
      process.env.WWF_RAPIDAPI_HOST &&
      process.env.WWF_DONATION_ENDPOINT
  );
}

async function sendWwfDonation(order, donation) {
  if (!donationConfigReady()) {
    return {
      status: "pending_configuration",
      message:
        "Donation is recorded, but live WWF API settings are not configured yet.",
    };
  }

  const payload = {
    partner: "World Wildlife Fund",
    orderId: order.id,
    paymentId: order.paymentId || "",
    amount: donation.amount,
    currency: "INR",
    source: "SnackRoots 2% sales pledge",
    customer: {
      name: order.customerName || "",
      email: order.customerEmail || "",
      phone: order.customerPhone || "",
    },
    items: Array.isArray(order.items)
      ? order.items.map((item) => ({
          name: item.name,
          quantity: item.qty || item.quantity || 1,
          price: item.price,
        }))
      : [],
  };

  const response = await fetch(process.env.WWF_DONATION_ENDPOINT, {
    method: process.env.WWF_DONATION_METHOD || "POST",
    headers: {
      "Content-Type": "application/json",
      "X-RapidAPI-Key": process.env.WWF_RAPIDAPI_KEY,
      "X-RapidAPI-Host": process.env.WWF_RAPIDAPI_HOST,
    },
    body: JSON.stringify(payload),
  });

  const text = await response.text();
  let providerResponse = text;
  try {
    providerResponse = text ? JSON.parse(text) : {};
  } catch {
    providerResponse = text;
  }

  if (!response.ok) {
    return {
      status: "failed",
      message: `WWF API returned ${response.status}`,
      providerResponse,
    };
  }

  return {
    status: "sent",
    sentAt: new Date().toISOString(),
    providerResponse,
  };
}

async function createDonationForOrder(order) {
  const donations = readJson(DONATIONS_FILE);
  const donation = {
    id: makeId("donation"),
    orderId: order.id,
    paymentId: order.paymentId || "",
    partner: "World Wildlife Fund",
    amount: calculateDonationAmount(order),
    currency: "INR",
    status: "pending",
    createdAt: new Date().toISOString(),
  };

  try {
    const result = await sendWwfDonation(order, donation);
    Object.assign(donation, result);
  } catch (error) {
    donation.status = "failed";
    donation.message = error.message;
  }

  donations.push(donation);
  writeJson(DONATIONS_FILE, donations);
  return donation;
}

app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "SnackRoots_Ultimate.html"));
});

app.get("/api/health", rateLimit("health", 120, 15 * 60 * 1000), (req, res) => {
  res.json({ ok: true, service: "SnackRoots API", time: new Date().toISOString() });
});

app.get("/api/orders", rateLimit("admin-read", 120, 15 * 60 * 1000), requireAdmin, (req, res) => {
  res.json(readJson(ORDERS_FILE));
});

app.get("/api/setup-status", rateLimit("admin-setup", 120, 15 * 60 * 1000), requireAdmin, (req, res) => {
  ensureStore();
  res.json(setupStatus());
});

app.get("/api/checkout-config", rateLimit("checkout-config", 120, 15 * 60 * 1000), (req, res) => {
  res.json({
    razorpayKeyId: process.env.RAZORPAY_KEY_ID || "",
    razorpayReady: Boolean(process.env.RAZORPAY_KEY_ID),
  });
});

app.get("/api/orders/export.csv", rateLimit("admin-export", 20, 15 * 60 * 1000), requireAdmin, (req, res) => {
  const csv = ordersToCsv(readJson(ORDERS_FILE));
  res.setHeader("Content-Type", "text/csv; charset=utf-8");
  res.setHeader(
    "Content-Disposition",
    `attachment; filename="snackroots-orders-${new Date().toISOString().slice(0, 10)}.csv"`
  );
  res.send(csv);
});

app.post("/api/recommend-snacks", rateLimit("recommend", 80, 15 * 60 * 1000), (req, res) => {
  res.json({
    query: req.body?.query || "",
    recommendations: recommendSnacks(req.body?.query),
  });
});

app.get("/api/orders/stats", rateLimit("admin-stats", 120, 15 * 60 * 1000), requireAdmin, (req, res) => {
  const orders = readJson(ORDERS_FILE);
  const donations = readJson(DONATIONS_FILE);
  const totalRevenue = orders.reduce(
    (sum, order) => sum + rupees(order.totalAmount),
    0
  );
  const donationTotal = donations.reduce(
    (sum, donation) => sum + rupees(donation.amount),
    0
  );

  res.json({
    orders: orders.length,
    totalOrders: orders.length,
    totalRevenue,
    donationTotal,
    openOrders: orders.filter((order) => !["delivered", "cancelled"].includes(order.status)).length,
    pendingOrders: orders.filter((order) => ["pending", "confirmed"].includes(order.status)).length,
    deliveredOrders: orders.filter((order) => order.status === "delivered").length,
    donationsSent: donations.filter((donation) => donation.status === "sent")
      .length,
    donationsPending: donations.filter((donation) =>
      ["pending", "pending_configuration", "failed"].includes(donation.status)
    ).length,
  });
});

app.post("/api/orders", rateLimit("create-order", 20, 15 * 60 * 1000), async (req, res) => {
  const validationError = validateOrderPayload(req.body || {});
  if (validationError) {
    res.status(400).json({ error: validationError });
    return;
  }

  const paymentCheck = await verifyRazorpayPayment(
    req.body.paymentId,
    req.body.totalAmount
  );
  if (!paymentCheck.verified) {
    res.status(paymentCheck.status || 402).json({ error: paymentCheck.error });
    return;
  }

  const orders = readJson(ORDERS_FILE);
  const order = {
    ...normalizeOrderPayload(req.body || {}),
    id: req.body.id || makeId("order"),
    status: cleanText(req.body.status, 40) || "confirmed",
    createdAt: req.body.createdAt || new Date().toISOString(),
  };
  if (paymentCheck.providerPayment) {
    order.razorpayVerified = true;
    order.razorpayCapturedAt = paymentCheck.providerPayment.created_at
      ? new Date(paymentCheck.providerPayment.created_at * 1000).toISOString()
      : new Date().toISOString();
  }

  const donation = await createDonationForOrder(order);
  order.donationAmount = donation.amount;
  order.donationStatus = donation.status;
  order.donationId = donation.id;

  orders.push(order);
  writeJson(ORDERS_FILE, orders);

  res.status(201).json({ order, donation });
});

app.patch("/api/orders/:id", rateLimit("admin-write", 60, 15 * 60 * 1000), requireAdmin, (req, res) => {
  const orders = readJson(ORDERS_FILE);
  const index = orders.findIndex((order) => order.id === req.params.id);
  if (index === -1) {
    res.status(404).json({ error: "Order not found" });
    return;
  }

  const status = cleanText(req.body.status, 40);
  if (!["pending", "confirmed", "shipped", "delivered", "cancelled"].includes(status)) {
    res.status(400).json({ error: "Invalid order status." });
    return;
  }

  orders[index] = {
    ...orders[index],
    status,
    updatedAt: new Date().toISOString(),
  };
  writeJson(ORDERS_FILE, orders);
  res.json(orders[index]);
});

app.get("/api/donations", rateLimit("admin-donations", 120, 15 * 60 * 1000), requireAdmin, (req, res) => {
  res.json(readJson(DONATIONS_FILE));
});

app.post("/api/donations/:id/retry", rateLimit("donation-retry", 20, 15 * 60 * 1000), requireAdmin, async (req, res) => {
  const donations = readJson(DONATIONS_FILE);
  const orders = readJson(ORDERS_FILE);
  const index = donations.findIndex((donation) => donation.id === req.params.id);
  if (index === -1) {
    res.status(404).json({ error: "Donation not found" });
    return;
  }

  const order = orders.find((item) => item.id === donations[index].orderId);
  if (!order) {
    res.status(404).json({ error: "Order not found for donation" });
    return;
  }

  const result = await sendWwfDonation(order, donations[index]);
  donations[index] = {
    ...donations[index],
    ...result,
    retryAt: new Date().toISOString(),
  };
  writeJson(DONATIONS_FILE, donations);
  res.json(donations[index]);
});

app.post("/api/razorpay/webhook", rateLimit("razorpay-webhook", 120, 15 * 60 * 1000), (req, res) => {
  const secret = process.env.RAZORPAY_WEBHOOK_SECRET;
  if (!secret) {
    res.status(503).json({ error: "Webhook secret is not configured" });
    return;
  }

  const expected = crypto
    .createHmac("sha256", secret)
    .update(req.rawBody || "")
    .digest("hex");

  const received = req.get("x-razorpay-signature") || "";
  if (
    expected.length !== received.length ||
    !crypto.timingSafeEqual(Buffer.from(expected), Buffer.from(received))
  ) {
    res.status(401).json({ error: "Invalid signature" });
    return;
  }

  const donations = readJson(DONATIONS_FILE);
  donations.push({
    id: makeId("webhook"),
    source: "razorpay",
    event: req.body.event,
    status: "received",
    createdAt: new Date().toISOString(),
    payload: req.body,
  });
  writeJson(DONATIONS_FILE, donations);
  res.json({ ok: true });
});

app.listen(PORT, () => {
  ensureStore();
  console.log(`SnackRoots server running at http://localhost:${PORT}`);
});

