# G.E.S.A.
Generate Express Secure Api cli for making a simple scaffold for node.js express


# in the CLI folder
npm i
npm link      # exposes `gesa`

# generate a JS project (default)
gesa new mysecureapi

# or a fully typed TS project
gesa new mysecureapi --ts

cd mysecureapi
cp .env.example .env
# For SQL (sqlite default): npx prisma generate
npm run dev
