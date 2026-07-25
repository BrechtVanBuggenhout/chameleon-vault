# Multi-stage Dockerfile for Chameleon Key Vault
# Stage 1: Builder
FROM node:22-alpine AS builder

WORKDIR /build

# Copy dependency files
COPY package*.json ./

# Install dependencies (including devDependencies for build)
RUN npm ci

# Copy source code
COPY tsconfig.json ./
COPY src ./src

# Build TypeScript → JavaScript
RUN npm run build

# Stage 2: Security scan & deps optimization
FROM node:22-alpine AS dependencies

WORKDIR /app

# Copy package files
COPY package*.json ./

# Install only production dependencies
RUN npm ci --only=production && \
    npm cache clean --force

# Stage 3: Runtime
FROM node:22-alpine

WORKDIR /app

# Add security labels
LABEL maintainer="Chameleon Team"
LABEL description="Cryptographic Key Vault Service for Project Chameleon"

# Create non-root user for security
RUN addgroup -g 1001 -S nodejs && \
    adduser -S nodejs -u 1001

# Copy production dependencies from dependencies stage
COPY --from=dependencies --chown=nodejs:nodejs /app/node_modules ./node_modules
COPY --from=dependencies --chown=nodejs:nodejs /app/package*.json ./

# Copy built application from builder stage
COPY --from=builder --chown=nodejs:nodejs /build/dist ./dist

# Set environment to production
ENV NODE_ENV=production

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD node -e "require('http').get('http://localhost:8080/health', (r) => {if (r.statusCode !== 200) throw new Error(r.statusCode)})"

# Switch to non-root user
USER nodejs

# Expose port
EXPOSE 8080

# Start application
CMD ["node", "dist/main.js"]
