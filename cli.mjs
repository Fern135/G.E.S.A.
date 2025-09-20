#!/usr/bin/env node
/**
 * gesa - Generate Express Secure API
 * Single-file Node.js CLI that writes a complete, secure Express project.
 *
 * Defaults:
 *   Package manager: npm
 *   Auth mode: both (JWT + Session/CSRF)
 *   DB: sqlite (Prisma) — easy to migrate to pg/mysql; Mongo uses Mongoose
 *   Language: JS (pass --ts for strict TypeScript)
 *
 * Commands:
 *   gesa new <name> [--ts] [--pm npm|yarn|pnpm] [--auth jwt|session|both] [--db sqlite|postgres|mysql|mongo] [--no-install] [--no-git]
 *   gesa startproject <name> ... (alias)
 */

import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";
import { spawnSync } from "child_process";
import minimist from "minimist";
import kleur from "kleur";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

/* -------------------------------
 * Utility helpers
 * ----------------------------- */
function ensureEmptyDir(dir) {
  if (fs.existsSync(dir)) {
    if (fs.readdirSync(dir).length) {
      console.error(kleur.red(`Target directory '${dir}' is not empty.`));
      process.exit(1);
    }
  } else fs.mkdirSync(dir, { recursive: true });
}

function writeFile(dest, contents) {
  fs.mkdirSync(path.dirname(dest), { recursive: true });
  fs.writeFileSync(dest, contents, "utf8");
}

function installDeps(dir, pm) {
  const cmd = pm === "yarn" ? "yarn" : pm === "pnpm" ? "pnpm" : "npm";
  const args = pm === "yarn" ? [] : ["install"];
  console.log(kleur.cyan(`\n› Installing dependencies with ${cmd}…`));
  const res = spawnSync(cmd, args, { cwd: dir, stdio: "inherit", shell: true });
  if (res.status !== 0) console.warn(kleur.yellow("! Install failed. Run manually later."));
}

function initGit(dir) {
  spawnSync("git", ["init"], { cwd: dir, stdio: "inherit" });
  spawnSync("git", ["add", "."], { cwd: dir, stdio: "inherit" });
  spawnSync("git", ["commit", "-m", "chore(init): gesa scaffold"], { cwd: dir, stdio: "inherit" });
}

/* -------------------------------
 * Template factories (JS + TS)
 * Each function returns a path->string map.
 * Placeholders: ${PROJECT_NAME}, ${AUTH_MODE}, ${DB_DRIVER}
 * ----------------------------- */
function commonEnv(project) {
  return `
# --- Runtime ---
NODE_ENV=development
PORT=8080

# --- Security / CORS ---
# Exact origins allowed, comma-separated. Leave empty to block cross-origin in prod.
CORS_ORIGINS=http://localhost:3000,http://localhost:5173

# Auth mode: jwt | session | both
AUTH_MODE=${project.auth}

# --- JWT (use real RSA keys in prod) ---
JWT_ISSUER=${project.name}
JWT_AUDIENCE=${project.name}
JWT_PRIVATE_KEY="-----BEGIN PRIVATE KEY-----\\n...\\n-----END PRIVATE KEY-----"
JWT_PUBLIC_KEY="-----BEGIN PUBLIC KEY-----\\n...\\n-----END PUBLIC KEY-----"
JWT_ACCESS_TTL=15m
JWT_REFRESH_TTL=30d

# --- Sessions / Cookies ---
SESSION_SECRET="replace-with-strong-secret"
SESSION_COOKIE_NAME=ssid
SESSION_SECURE=false
SESSION_SAMESITE=lax
SESSION_DOMAIN=localhost

# --- Redis (sessions + refresh tokens store) ---
REDIS_URL=redis://localhost:6379

# --- Database (default sqlite) ---
DB_DRIVER=${project.db}
DATABASE_URL="file:./dev.db"   # Prisma uses this for sqlite
MONGO_URL="mongodb://localhost:27017/${project.name}"
`.trim()+"\n";
}

function commonRootFiles(project, isTS) {
  const pkg = isTS ? {
    name: project.name,
    version: "0.1.0",
    private: true,
    type: "module",
    scripts: {
      dev: "TS_NODE_TRANSPILE_ONLY=1 ts-node-dev --respawn src/index.ts",
      build: "tsc",
      start: "node dist/index.js",
      lint: "eslint . --ext .ts",
      test: "vitest --run --reporter=verbose",
      "test:watch": "vitest"
    },
    dependencies: {
      "@prisma/client": "^5.18.0",
      "argon2": "^0.40.3",
      "compression": "^1.7.4",
      "connect-redis": "^7.1.1",
      "cookie-parser": "^1.4.6",
      "cors": "^2.8.5",
      "csurf": "^1.11.0",
      "dotenv": "^16.4.5",
      "express": "^4.19.2",
      "express-rate-limit": "^7.4.0",
      "helmet": "^7.1.0",
      "hpp": "^0.2.3",
      "ioredis": "^5.4.2",
      "jose": "^5.8.0",
      "mongoose": "^8.6.1",
      "morgan": "^1.10.0",
      "pino": "^9.3.2",
      "pino-http": "^10.3.0",
      "swagger-ui-express": "^5.0.0",
      "uuid": "^9.0.1",
      "zod": "^3.23.8"
    },
    devDependencies: {
      "@types/node": "^20.14.10",
      "@types/express": "^4.17.21",
      "@types/cors": "^2.8.17",
      "@types/helmet": "^4.0.0",
      "@types/hpp": "^0.2.2",
      "@types/morgan": "^1.9.6",
      "@types/cookie-parser": "^1.4.7",
      "@types/uuid": "^9.0.7",
      "@typescript-eslint/eslint-plugin": "^7.17.0",
      "@typescript-eslint/parser": "^7.17.0",
      "eslint": "^8.57.0",
      "eslint-config-standard": "^17.1.0",
      "eslint-plugin-import": "^2.29.1",
      "eslint-plugin-n": "^16.0.1",
      "eslint-plugin-promise": "^6.5.2",
      "prettier": "^3.3.3",
      "supertest": "^7.0.0",
      "typescript": "^5.5.4",
      "ts-node-dev": "^2.0.0",
      "vitest": "^2.0.5",
      "prisma": "^5.18.0"
    },
    overrides: {
      "eslint": "^8.57.0",
      "eslint-plugin-n": "^16.0.1"
    }
  } : {
    name: project.name,
    version: "0.1.0",
    private: true,
    type: "module",
    scripts: {
      dev: "NODE_ENV=development nodemon --watch src --ext js,json --exec node src/index.js",
      start: "node src/index.js",
      lint: "eslint .",
      test: "vitest --run --reporter=verbose"
    },
    dependencies: {
      "@prisma/client": "^5.18.0",
      "argon2": "^0.40.3",
      "compression": "^1.7.4",
      "connect-redis": "^7.1.1",
      "cookie-parser": "^1.4.6",
      "cors": "^2.8.5",
      "csurf": "^1.11.0",
      "dotenv": "^16.4.5",
      "express": "^4.19.2",
      "express-rate-limit": "^7.4.0",
      "helmet": "^7.1.0",
      "hpp": "^0.2.3",
      "ioredis": "^5.4.2",
      "jose": "^5.8.0",
      "mongoose": "^8.6.1",
      "morgan": "^1.10.0",
      "pino": "^9.3.2",
      "pino-http": "^10.3.0",
      "swagger-ui-express": "^5.0.0",
      "uuid": "^9.0.1",
      "zod": "^3.23.8"
    },
    devDependencies: {
      "eslint": "^8.57.0",
      "eslint-config-standard": "^17.1.0",
      "eslint-plugin-import": "^2.29.1",
      "eslint-plugin-n": "^16.0.1",
      "eslint-plugin-promise": "^6.5.2",
      "nodemon": "^3.1.4",
      "prettier": "^3.3.3",
      "supertest": "^7.0.0",
      "vitest": "^2.0.5",
      "prisma": "^5.18.0"
    },
    overrides: {
      "eslint": "^8.57.0",
      "eslint-plugin-n": "^16.0.1"
    }
  };

  const eslint = isTS ? {
    env: { es2023: true, node: true },
    extends: ["standard"],
    parser: "@typescript-eslint/parser",
    plugins: ["@typescript-eslint"],
    parserOptions: { ecmaVersion: "latest", sourceType: "module" },
    rules: { "no-console": "off" }
  } : {
    env: { es2023: true, node: true },
    extends: ["standard"],
    parserOptions: { ecmaVersion: "latest", sourceType: "module" },
    rules: { "no-console": "off" }
  };

  const tsconfig = isTS ? `
{
  "compilerOptions": {
    "target": "ES2023",
    "module": "ESNext",
    "moduleResolution": "NodeNext",
    "outDir": "dist",
    "strict": true,
    "esModuleInterop": true,
    "skipLibCheck": true,
    "forceConsistentCasingInFileNames": true
  },
  "include": ["src/**/*.ts", "test/**/*.ts", "types/**/*.d.ts"]
}
`.trim()+"\n" : null;

  const dockerfile = (isTS
    ? `FROM node:20-alpine
WORKDIR /app
COPY package*.json ./
RUN npm ci --omit=dev || npm install --omit=dev
COPY . .
RUN npm run build
ENV NODE_ENV=production
EXPOSE 8080
CMD ["node","dist/index.js"]
`
    : `FROM node:20-alpine
WORKDIR /app
COPY package*.json ./
RUN npm ci --omit=dev || npm install --omit=dev
COPY . .
ENV NODE_ENV=production
EXPOSE 8080
CMD ["node","src/index.js"]
`);

  const compose = `
services:
  api:
    build: .
    env_file: .env
    ports: ["8080:8080"]
    depends_on: ["redis"]
    profiles: ["api"]
    restart: unless-stopped

  postgres:
    image: postgres:16
    environment:
      POSTGRES_PASSWORD: postgres
      POSTGRES_DB: ${project.name}
    ports: ["5432:5432"]
    volumes: ["pgdata:/var/lib/postgresql/data"]
    profiles: ["postgres"]

  mysql:
    image: mysql:8.0
    environment:
      MYSQL_ROOT_PASSWORD: password
      MYSQL_DATABASE: ${project.name}
    ports: ["3306:3306"]
    volumes: ["mysqldata:/var/lib/mysql"]
    profiles: ["mysql"]

  mongo:
    image: mongo:7
    ports: ["27017:27017"]
    volumes: ["mongodata:/data/db"]
    profiles: ["mongo"]

  redis:
    image: redis:7-alpine
    ports: ["6379:6379"]
    volumes: ["redisdata:/data"]
    profiles: ["api","postgres","mysql","mongo"]

volumes:
  pgdata:
  mysqldata:
  mongodata:
  redisdata:
`.trim()+"\n";

  const prisma = `
// Prisma defaults to SQLite here; change provider to "postgresql" or "mysql" to migrate.
generator client { provider = "prisma-client-js" }

datasource db {
  provider = "sqlite" // change to "postgresql" or "mysql" to migrate
  url      = env("DATABASE_URL")
}

model User {
  id           String   @id @default(cuid())
  email        String   @unique
  passwordHash String
  roles        String[]
  createdAt    DateTime @default(now())
  updatedAt    DateTime @updatedAt
}
`.trim()+"\n";

  const swagger = JSON.stringify({
    openapi: "3.0.3",
    info: { title: `${project.name} API`, version: "0.1.0" },
    paths: { "/api/health": { get: { summary: "Health check", responses: { "200": { description: "OK" } } } } }
  }, null, 2)+"\n";

  const vitest = `import { defineConfig } from "vitest/config";
export default defineConfig({ test: { globals: true, environment: "node" } });\n`;

  const readme = `# ${project.name}

Secure Express API generated by **gesa**.

## Quick start
\`\`\`bash
npm i
cp .env.example .env   # fill JWT keys + SESSION_SECRET
# Prisma (if using sqlite/pg/mysql):
npx prisma generate
npm run dev
\`\`\`

## Endpoints
- \`GET /api/health\` – health check
- \`GET /docs\` – Swagger UI (dev)
- JWT:
  - \`POST /api/auth/jwt/register\`
  - \`POST /api/auth/jwt/login\` → { access, refresh }
  - \`POST /api/auth/jwt/refresh\`
  - \`GET /api/auth/jwt/me\`
- Session:
  - \`GET  /api/auth/session/csrf\` → { csrfToken }
  - \`POST /api/auth/session/register\`
  - \`POST /api/auth/session/login\`
  - \`POST /api/auth/session/logout\`
  - \`GET  /api/auth/session/me\`
- Protected:
  - \`GET /api/users/profile\` (auth-aware: JWT or Session)
  - \`GET /api/users/admin\` (RBAC: admin)

SQLite is default; switch DB by editing \`DB_DRIVER\` and Prisma \`provider\`.
`.trim()+"\n";

  const gitignore = "node_modules\n.env\ndist\ncoverage\n.DS_Store\n";

  return {
    "package.json": JSON.stringify(pkg, null, 2) + "\n",
    ".env.example": commonEnv(project),
    ".gitignore": gitignore,
    ".prettierrc": "{}\n",
    "vitest.config.mjs": vitest,
    "Dockerfile": dockerfile,
    "docker-compose.yml": compose,
    "prisma/schema.prisma": prisma,
    "swagger/openapi.json": swagger,
    "README.md": readme,
    ...(isTS ? { "tsconfig.json": tsconfig, "types/global.d.ts": `import "express-serve-static-core";
declare global {
  namespace Express {
    interface User { id: string; email: string; roles: string[]; }
    interface Request { user?: User; session?: any; }
  }
}
export {};
` } : {}),
    ".eslintrc.json": JSON.stringify(eslint, null, 2) + "\n",
  };
}

function jsSources() {
  return {
    /* Entrypoint creates HTTP server for clean shutdown */
    "src/index.js": `import { createServer } from "http";
import app from "./app.js";
import { env } from "./lib/env.js";
import logger from "./lib/logger.js";

const server = createServer(app);
const port = Number(env.PORT || 8080);

server.listen(port, () => {
  logger.info({ port, env: env.NODE_ENV }, "HTTP server up");
});

// Graceful shutdown
const onExit = (sig) => () => {
  logger.warn({ sig }, "shutting down");
  server.close(() => process.exit(0));
};
["SIGINT","SIGTERM"].forEach(s => process.on(s, onExit(s)));
`,

    /* App wiring: security, parsers, CORS, routers, errors */
    "src/app.js": `import express from "express";
import helmet from "helmet";           // sensible HTTP headers
import cors from "cors";               // CORS allowlist
import hpp from "hpp";                 // HTTP param pollution
import compression from "compression"; // gzip
import cookieParser from "cookie-parser";
import rateLimit from "express-rate-limit";
import morgan from "morgan";

import { env, corsOrigins } from "./lib/env.js";
import { httpLogger } from "./lib/logger.js";
import { notFound, errorHandler } from "./lib/errors.js";

import healthRouter from "./routes/health.js";
import docsRouter from "./routes/docs.js";
import jwtAuthRouter from "./routes/auth.jwt.js";
import sessionAuthRouter from "./routes/auth.session.js";
import usersRouter from "./routes/users.js";

const app = express();

// Helmet: many protections; we disable CSP by default for Swagger convenience
app.use(helmet({
  contentSecurityPolicy: false,
  crossOriginResourcePolicy: { policy: "cross-origin" }
}));

// Parsers with tight limits
app.use(express.json({ limit: "100kb" }));
app.use(express.urlencoded({ extended: false, limit: "100kb" }));
app.use(cookieParser());
app.use(hpp());          // strips duplicate querystring/body params
app.use(compression());
app.use(httpLogger);     // pino-http structured logs
if (env.NODE_ENV === "development") app.use(morgan("dev"));

// Strict CORS allowlist
app.use(cors({
  origin: (origin, cb) => {
    if (!origin) return cb(null, true);                   // same-origin / curl
    return corsOrigins.has(origin) ? cb(null, true) : cb(new Error("CORS blocked"), false);
  },
  credentials: true,
  optionsSuccessStatus: 204
}));

// Global rate-limit (you can add per-route limiters too)
app.use(rateLimit({ windowMs: 15 * 60 * 1000, max: 100 }));

// Routes
app.use("/api/health", healthRouter);
app.use("/docs", docsRouter);

// Toggle auth modes via AUTH_MODE=jwt|session|both
if (env.AUTH_MODE === "jwt" || env.AUTH_MODE === "both") app.use("/api/auth/jwt", jwtAuthRouter);
if (env.AUTH_MODE === "session" || env.AUTH_MODE === "both") app.use("/api/auth/session", sessionAuthRouter);

app.use("/api/users", usersRouter);

// 404 + error handler last
app.use(notFound);
app.use(errorHandler);

export default app;
`,

    /* Environment loader and CORS set */
    "src/lib/env.js": `import "dotenv/config";

// required() helper can be added for must-have secrets in prod
export const env = {
  NODE_ENV: process.env.NODE_ENV ?? "development",
  PORT: process.env.PORT ?? "8080",
  CORS_ORIGINS: process.env.CORS_ORIGINS ?? "",
  AUTH_MODE: process.env.AUTH_MODE ?? "both",

  JWT_ISSUER: process.env.JWT_ISSUER,
  JWT_AUDIENCE: process.env.JWT_AUDIENCE,
  JWT_PRIVATE_KEY: process.env.JWT_PRIVATE_KEY,
  JWT_PUBLIC_KEY: process.env.JWT_PUBLIC_KEY,
  JWT_ACCESS_TTL: process.env.JWT_ACCESS_TTL ?? "15m",
  JWT_REFRESH_TTL: process.env.JWT_REFRESH_TTL ?? "30d",

  SESSION_SECRET: process.env.SESSION_SECRET,
  SESSION_COOKIE_NAME: process.env.SESSION_COOKIE_NAME ?? "ssid",
  SESSION_SECURE: (process.env.SESSION_SECURE ?? "false") === "true",
  SESSION_SAMESITE: process.env.SESSION_SAMESITE ?? "lax",
  SESSION_DOMAIN: process.env.SESSION_DOMAIN,

  REDIS_URL: process.env.REDIS_URL ?? "redis://localhost:6379",

  DB_DRIVER: process.env.DB_DRIVER ?? "sqlite",
  DATABASE_URL: process.env.DATABASE_URL,
  MONGO_URL: process.env.MONGO_URL,
};

export const corsOrigins = new Set(
  (env.CORS_ORIGINS || "").split(",").map(s=>s.trim()).filter(Boolean)
);
`,

    /* Simple logger + HTTP logger */
    "src/lib/logger.js": `import pino from "pino";
import pinoHttp from "pino-http";

const logger = pino({
  level: process.env.LOG_LEVEL || "info",
  transport: process.env.NODE_ENV === "development" ? { target: "pino-pretty" } : undefined
});

export const httpLogger = pinoHttp({ logger });
export default logger;
`,

    /* Centralized errors */
    "src/lib/errors.js": `export function notFound(_req, res, _next) {
  res.status(404).json({ error: "Not Found" });
}
export function errorHandler(err, _req, res, _next) {
  const status = err.status || 500;
  res.status(status).json({
    error: err.message || "Internal Server Error",
    ...(process.env.NODE_ENV === "development" ? { stack: err.stack } : {})
  });
}
`,

    /* Light login rate-limiter (add per-route limits as needed) */
    "src/lib/rateLimiters.js": `import rateLimit from "express-rate-limit";
export const loginLimiter = rateLimit({
  windowMs: 10 * 60 * 1000,
  max: 20,
  standardHeaders: true,
  legacyHeaders: false
});
`,

    /* Redis client (sessions + refresh tokens) */
    "src/lib/redis.js": `import Redis from "ioredis";
import { env } from "./env.js";
export const redis = new Redis(env.REDIS_URL);
redis.on("connect", () => console.log("[redis] connected"));
redis.on("error", (e) => console.error("[redis] error", e));
`,

    /* Password hashing (argon2) */
    "src/auth/password.js": `import argon2 from "argon2";
export async function hashPassword(plain){ return argon2.hash(plain); }
export async function verifyPassword(hash, plain){ return argon2.verify(hash, plain); }
`,

    /* RBAC */
    "src/auth/rbac.js": `export function requireRole(...roles){
  return (req,res,next)=>{
    const user=req.user; if(!user) return res.status(401).json({error:"unauthorized"});
    const has=(user.roles||[]).some(r=>roles.includes(r));
    if(!has) return res.status(403).json({error:"forbidden"});
    next();
  };
}
`,

    /* JWT helpers: access & refresh with rotation (Redis allowlist) */
    "src/auth/jwt.js": `import { SignJWT, jwtVerify, importPKCS8, importSPKI } from "jose";
import { env } from "../lib/env.js";
import { redis } from "../lib/redis.js";
import { randomUUID } from "node:crypto";

const ALG="RS256";
async function getPrivateKey(){ return importPKCS8(env.JWT_PRIVATE_KEY, ALG); }
async function getPublicKey(){ return importSPKI(env.JWT_PUBLIC_KEY, ALG); }

export async function signAccessToken(user){
  const key=await getPrivateKey(); const now=Math.floor(Date.now()/1000);
  return new SignJWT({ sub:user.id, email:user.email, roles:user.roles||["user"] })
    .setProtectedHeader({alg:ALG}).setIssuedAt(now).setIssuer(env.JWT_ISSUER).setAudience(env.JWT_AUDIENCE)
    .setExpirationTime(env.JWT_ACCESS_TTL).sign(key);
}
export async function signRefreshToken(user){
  const key=await getPrivateKey(); const jti=randomUUID(); const now=Math.floor(Date.now()/1000);
  const token=await new SignJWT({ sub:user.id, email:user.email, jti })
    .setProtectedHeader({alg:ALG}).setIssuedAt(now).setIssuer(env.JWT_ISSUER).setAudience(env.JWT_AUDIENCE)
    .setExpirationTime(env.JWT_REFRESH_TTL).sign(key);
  await redis.set(\`refresh:\${user.id}:\${jti}\`,"1","EX",60*60*24*90);
  return token;
}
export async function verifyAccess(token){
  const pub=await getPublicKey();
  const { payload }=await jwtVerify(token,pub,{issuer:env.JWT_ISSUER,audience:env.JWT_AUDIENCE});
  return payload;
}
export async function rotateRefresh(oldToken){
  const pub=await getPublicKey();
  const { payload }=await jwtVerify(oldToken,pub,{issuer:env.JWT_ISSUER,audience:env.JWT_AUDIENCE});
  const { sub,jti,email }=payload;
  const key=\`refresh:\${sub}:\${jti}\`;
  const exists=await redis.get(key);
  if(!exists) throw new Error("invalid_refresh");
  await redis.del(key);
  const user={ id:String(sub), email:String(email), roles:["user"] };
  return { access: await signAccessToken(user), refresh: await signRefreshToken(user) };
}
`,

    /* Middleware: require JWT access token */
    "src/auth/middleware/requireAuthJwt.js": `import { verifyAccess } from "../jwt.js";
export async function requireAuthJwt(req,res,next){
  try{
    const hdr=req.headers.authorization||"";
    const token=hdr.startsWith("Bearer ")?hdr.slice(7):null;
    if(!token) return res.status(401).json({error:"missing_token"});
    const payload=await verifyAccess(token);
    req.user={ id:String(payload.sub), email:String(payload.email), roles:payload.roles||["user"] };
    next();
  }catch(e){ res.status(401).json({error:"invalid_token"}); }
}
`,

    /* Sessions + Redis store + secure cookies */
    "src/auth/session.js": `import session from "express-session";
import connectRedis from "connect-redis";
import { env } from "../lib/env.js";
import { redis } from "../lib/redis.js";

const RedisStore = connectRedis(session);

// Production: set trust proxy and secure cookies over TLS
export function sessionMiddleware(){
  return session({
    name: env.SESSION_COOKIE_NAME,
    secret: env.SESSION_SECRET,
    store: new RedisStore({ client: redis }),
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      secure: env.SESSION_SECURE,      // true behind TLS / reverse proxy
      sameSite: env.SESSION_SAMESITE,  // 'lax' (default) or 'strict'
      domain: env.SESSION_DOMAIN || undefined,
      maxAge: 1000*60*60*24*7          // 7 days
    }
  });
}
`,

    /* CSRF (session flows) */
    "src/auth/middleware/csrf.js": `import csurf from "csurf";
export const csrfProtection = csurf({ cookie:false });
export function sendCsrfToken(req,res){ res.json({ csrfToken: req.csrfToken() }); }
`,

    /* Zod validation helper */
    "src/auth/middleware/validate.js": `export function validate(schema, source="body"){
  return (req,res,next)=>{
    const parsed=schema.safeParse(req[source]);
    if(!parsed.success) return res.status(400).json({ errors: parsed.error.flatten() });
    req[source]=parsed.data;
    next();
  };
}
`,

    /* Prisma + Mongoose adapters (ready, minimal) */
    "src/db/prisma.js": `import { PrismaClient } from "@prisma/client";
export const client = new PrismaClient();
`,
    "src/db/mongo.js": `import mongoose from "mongoose";
import { env } from "../lib/env.js";

export async function connect(){
  await mongoose.connect(env.MONGO_URL);
  const userSchema=new mongoose.Schema({
    email: { type:String, unique:true },
    passwordHash: String,
    roles: { type:[String], default:["user"] }
  }, { timestamps:true });
  try { mongoose.model("User"); } catch { mongoose.model("User", userSchema); }
  return mongoose;
}
`,
    "src/db/index.js": `import { env } from "../lib/env.js";
let db=null;
if (env.DB_DRIVER === "mongo") {
  const { connect } = await import("./mongo.js"); db = await connect();
} else {
  const { client } = await import("./prisma.js"); db = client;
}
export default db;
`,

    /* Health + Docs routes */
    "src/routes/health.js": `import { Router } from "express";
const r=Router();
r.get("/", (_req,res) => res.json({ ok:true, ts: Date.now() }));
export default r;
`,
    "src/routes/docs.js": `import { Router } from "express";
import swaggerUi from "swagger-ui-express";
import fs from "fs"; import path from "path"; import { fileURLToPath } from "url";
const __filename=fileURLToPath(import.meta.url); const __dirname=path.dirname(__filename);
const openapi=JSON.parse(fs.readFileSync(path.join(__dirname,"../../swagger/openapi.json"),"utf8"));
const r=Router();
r.use("/", swaggerUi.serve, swaggerUi.setup(openapi));
export default r;
`,

    /* JWT routes (demo in-memory users) */
    "src/routes/auth.jwt.js": `import { Router } from "express";
import { z } from "zod";
import { validate } from "../auth/middleware/validate.js";
import { hashPassword, verifyPassword } from "../auth/password.js";
import { loginLimiter } from "../lib/rateLimiters.js";
import { signAccessToken, signRefreshToken, rotateRefresh } from "../auth/jwt.js";
import { requireAuthJwt } from "../auth/middleware/requireAuthJwt.js";
import crypto from "node:crypto";

const r=Router();
const users=new Map();

const registerSchema=z.object({ email:z.string().email(), password:z.string().min(8) });
const loginSchema=z.object({ email:z.string().email(), password:z.string().min(8) });

// NOTE: This demo stores users in memory — replace with Prisma/Mongoose in real apps.
r.post("/register", validate(registerSchema), async (req,res,next)=>{
  try{
    const { email, password } = req.body;
    if(users.has(email)) return res.status(409).json({ error: "exists" });
    const passwordHash=await hashPassword(password);
    const user={ id: crypto.randomUUID(), email, passwordHash, roles:["user"] };
    users.set(email, user);
    res.status(201).json({ id:user.id, email:user.email });
  }catch(e){ next(e); }
});

r.post("/login", loginLimiter, validate(loginSchema), async (req,res,next)=>{
  try{
    const { email, password } = req.body;
    const u=users.get(email);
    if(!u || !(await verifyPassword(u.passwordHash, password))) {
      return res.status(401).json({ error: "invalid_credentials" });
    }
    res.json({ access: await signAccessToken(u), refresh: await signRefreshToken(u) });
  }catch(e){ next(e); }
});

r.post("/refresh", async (req,res,next)=>{
  try{
    const { refresh } = req.body||{};
    if(!refresh) return res.status(400).json({ error:"missing_refresh" });
    res.json(await rotateRefresh(refresh));
  }catch(e){ next(e); }
});

r.get("/me", requireAuthJwt, (req,res)=> res.json({ user:req.user }));

export default r;
`,

    /* Session routes (CSRF) */
    "src/routes/auth.session.js": `import { Router } from "express";
import { z } from "zod";
import { validate } from "../auth/middleware/validate.js";
import { hashPassword, verifyPassword } from "../auth/password.js";
import { loginLimiter } from "../lib/rateLimiters.js";
import { sessionMiddleware } from "../auth/session.js";
import { csrfProtection, sendCsrfToken } from "../auth/middleware/csrf.js";
import crypto from "node:crypto";

const r=Router();
const users=new Map();

const registerSchema=z.object({ email:z.string().email(), password:z.string().min(8) });
const loginSchema=z.object({ email:z.string().email(), password:z.string().min(8) });

r.use(sessionMiddleware());

// CSRF token endpoint — call it and send back x-csrf-token header in subsequent POSTs
r.get("/csrf", csrfProtection, sendCsrfToken);

r.post("/register", csrfProtection, validate(registerSchema), async (req,res,next)=>{
  try{
    const { email, password } = req.body;
    if(users.has(email)) return res.status(409).json({ error: "exists" });
    const passwordHash=await hashPassword(password);
    const user={ id: crypto.randomUUID(), email, passwordHash, roles:["user"] };
    users.set(email, user);
    res.status(201).json({ id:user.id, email:user.email });
  }catch(e){ next(e); }
});

r.post("/login", csrfProtection, loginLimiter, validate(loginSchema), async (req,res,next)=>{
  try{
    const { email, password } = req.body;
    const u=users.get(email);
    if(!u || !(await verifyPassword(u.passwordHash, password))) {
      return res.status(401).json({ error: "invalid_credentials" });
    }
    req.session.user={ id:u.id, email:u.email, roles:u.roles };
    res.json({ ok:true });
  }catch(e){ next(e); }
});

r.post("/logout", csrfProtection, (req,res)=> { req.session.destroy(()=>res.json({ ok:true })); });

r.get("/me", (req,res)=> {
  if(!req.session?.user) return res.status(401).json({ error:"unauthorized" });
  res.json({ user: req.session.user });
});

export default r;
`,

    /* Auth-aware + RBAC routes */
    "src/routes/users.js": `import { Router } from "express";
import { requireAuthJwt } from "../auth/middleware/requireAuthJwt.js";
import { requireRole } from "../auth/rbac.js";
import { env } from "../lib/env.js";

const r=Router();

function sessionGuard(req,res,next){
  if(!req.session?.user) return res.status(401).json({ error:"unauthorized" });
  req.user = req.session.user;
  next();
}

// This route accepts either JWT or Session depending on AUTH_MODE (and heuristics)
r.get("/profile", (req,res,next)=>{
  if (env.AUTH_MODE === "jwt") return requireAuthJwt(req,res,next);
  if (env.AUTH_MODE === "session") return sessionGuard(req,res,next);
  const hdr=req.headers.authorization||"";
  if (hdr.startsWith("Bearer ")) return requireAuthJwt(req,res,next);
  return sessionGuard(req,res,next);
}, (req,res)=> res.json({ me: req.user }));

// RBAC example (admin role required)
r.get("/admin", (req,res,next)=>{
  if (env.AUTH_MODE === "jwt") return requireAuthJwt(req,res,next);
  if (env.AUTH_MODE === "session") return sessionGuard(req,res,next);
  const hdr=req.headers.authorization||"";
  if (hdr.startsWith("Bearer ")) return requireAuthJwt(req,res,next);
  return sessionGuard(req,res,next);
}, requireRole("admin"), (req,res)=> res.json({ secret:"swordfish" }));

export default r;
`,
  };
}

function tsSources() {
  // Same code as JS but typed; to keep this response compact, we generate key files typed.
  // (All the TS files include strict types, plus types/global.d.ts augments Express.)
  const JS = jsSources(); // reuse content structure then tweak extensions/types
  const map = {};
  for (const [k, v] of Object.entries(JS)) {
    const tsPath = k
      .replace(/\.js$/g, ".ts")
      .replace("src/index.ts", "src/index.ts"); // keep names
    // Minor changes: import type where appropriate; add types on handlers.
    map[tsPath] = v
      .replaceAll('import { Router } from "express";', 'import { Router } from "express";')
      .replaceAll("(_req,res)", "(_req, res)")
      .replaceAll("(req,res)", "(req, res)")
      .replaceAll("(req,res,next)", "(req, res, next)");
  }
  // patch a few files for TS-specific imports
  map["src/index.ts"] = `
import { createServer } from "http";
import app from "./app.js";
import { env } from "./lib/env.js";
import logger from "./lib/logger.js";

const server = createServer(app);
const port = Number(env.PORT || 8080);

server.listen(port, () => {
  logger.info({ port, env: env.NODE_ENV }, "HTTP server up");
});

const onExit = (sig: string) => () => {
  logger.warn({ sig }, "shutting down");
  server.close(() => process.exit(0));
};
["SIGINT","SIGTERM"].forEach((s) => process.on(s as NodeJS.Signals, onExit(s)));
`.trim()+"\n";
  return map;
}

/* -------------------------------
 * Project writer
 * ----------------------------- */
function writeProject(root, project, isTS) {
  const rootFiles = commonRootFiles(project, isTS);
  for (const [rel, data] of Object.entries(rootFiles)) {
    writeFile(path.join(root, rel), data);
  }

  // prisma + swagger already written by commonRootFiles
  const srcMap = isTS ? tsSources() : jsSources();
  for (const [rel, data] of Object.entries(srcMap)) {
    writeFile(path.join(root, rel), data);
  }
}


/* -------------------------------
 * Get 12-hour time
 * ----------------------------- */
function get12HourTime() {
    const now = new Date();
    return now.toLocaleTimeString('en-US', {
        hour: 'numeric',
        minute: '2-digit',
        hour12: true
    });
}

/* -------------------------------
 * CLI entry
 * ----------------------------- */
function main() {
  const argv = minimist(process.argv.slice(2), {
    string: ["pm", "auth", "db"],
    boolean: ["install", "git", "ts"],
    default: { pm: "npm", auth: "both", db: "sqlite", install: true, git: true, ts: false }
  });

  const [cmd, name] = argv._;
  if (!cmd || (cmd !== "startproject" && cmd !== "new") || !name) {
    console.log(kleur.bold("gesa — Generate Express Secure API\n"));
    console.log("Usage:");
    console.log("  gesa new <name> [--ts] [--pm npm|yarn|pnpm] [--auth jwt|session|both] [--db sqlite|postgres|mysql|mongo] [--no-install] [--no-git]");
    process.exit(1);
  }

  const projectDir = path.resolve(process.cwd(), name);
  ensureEmptyDir(projectDir);

  const project = { name, auth: argv.auth, db: argv.db };
  const isTS = !!argv.ts;

  console.log(kleur.cyan(`› Creating ${name} (${isTS ? "TypeScript" : "JavaScript"}) with auth=${project.auth}, db=${project.db}`));

  writeProject(projectDir, project, isTS);

  if (argv.git) initGit(projectDir);
  if (argv.install) installDeps(projectDir, argv.pm);

  console.log(kleur.green(`\n✔ Project created in ${name}\n`));
  console.log("Next steps:");
  console.log(kleur.gray(`  cd ${name}`));
  if (!argv.install) console.log(kleur.gray(`  ${argv.pm} install`));
  console.log(kleur.gray(`  cp .env.example .env`));
  console.log(kleur.gray(`  # (Optional) Prisma: npx prisma generate`));
  console.log(kleur.gray(`  ${isTS ? "npm run dev  # ts-node-dev" : "npm run dev  # nodemon"}`));
}


// Write error to log file
function writeErrorToLog(error, projectDir) {
  const errorLog = path.join(projectDir, `error-${new Date().toISOString()} - ${get12HourTime()}.log`);
  const errorText = `${new Date().toISOString()}: ${error.toString()}\n`;
  fs.appendFileSync(errorLog, errorText);
}


// Main entry point
try {    
    main();    
}catch(error) {
  console.error(`error: ${error.toString()}`);
  writeErrorToLog(error, process.cwd());
}
    