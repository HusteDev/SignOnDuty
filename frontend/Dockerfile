# SvelteKit frontend with pnpm and Node adapter
FROM node:20-alpine AS builder

WORKDIR /app

# Install pnpm
RUN npm install -g pnpm

# Copy package files
COPY package.json pnpm-lock.yaml* ./

# Install dependencies with pnpm
RUN pnpm install --frozen-lockfile

# Copy source code
COPY . .

# Build the application with Node adapter
RUN pnpm run build

# Runtime stage
FROM node:20-alpine

WORKDIR /app

# Install pnpm
RUN npm install -g pnpm

# Copy built application from builder
COPY --from=builder /app/build ./build
COPY --from=builder /app/node_modules ./node_modules
COPY --from=builder /app/package.json ./

# Create non-root user (use different UID if 1000 is taken)
RUN addgroup -g 1001 svelte && \
    adduser -D -u 1001 -G svelte svelte && \
    chown -R svelte:svelte /app

USER svelte

EXPOSE 3000

HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD wget --no-verbose --tries=1 --spider http://localhost:3000 || exit 1

# Run the built SvelteKit app with Node adapter
# The adapter automatically serves static files from build/client/
CMD ["node", "build/index.js"]
