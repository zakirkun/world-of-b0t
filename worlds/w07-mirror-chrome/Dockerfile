# ---- build stage: compile TypeScript ----
FROM node:22-alpine AS build
WORKDIR /app
COPY package.json tsconfig.json ./
RUN npm install
COPY src/ ./src/
RUN npm run build

# ---- runtime stage: compiled JS only ----
FROM node:22-alpine
WORKDIR /app
COPY --from=build /app/dist ./dist

# Flag is injected at runtime as an env var; never baked into a layer.
ENV W0B_FLAG=""
ENV INTERNAL_URL=""
EXPOSE 3000
CMD ["node", "dist/server.js"]
