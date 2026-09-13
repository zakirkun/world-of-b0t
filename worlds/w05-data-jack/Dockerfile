FROM node:22-alpine

# better-sqlite3 needs a toolchain to build its native addon.
RUN apk add --no-cache python3 make g++

WORKDIR /app
COPY package.json ./
RUN npm install --omit=dev

COPY app.js ./

# Flag is injected at runtime as an env var; never baked into a layer.
ENV W0B_FLAG=""
EXPOSE 3000
CMD ["node", "app.js"]
