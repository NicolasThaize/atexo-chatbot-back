# Multi-stage build for Angular 18 application
FROM node:18-alpine AS build

# Set working directory
WORKDIR /app

# Copy package files
COPY package*.json ./

# Install all dependencies (including dev dependencies needed for build)
RUN npm ci --legacy-peer-deps

# Copy source code
COPY . .

# Build the application with development configuration (more relaxed budget limits)
RUN npm run build -- --configuration=development

# Production stage
FROM node:18-alpine AS production

# Install serve package globally
RUN npm install -g serve

# Set working directory
WORKDIR /app

# Copy built application from build stage
COPY --from=build /app/dist/atexo-chatbot-stagiaires/browser ./dist

# Expose port
EXPOSE 4200

# Start the application
CMD ["serve", "-s", "dist", "-l", "4200"]
