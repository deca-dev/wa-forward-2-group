# FROM node:16-alpine

# ENV NODE_OPTIONS=--openssl-legacy-provider

# WORKDIR /app

# # Install build dependencies including git
# RUN apk add --no-cache python3 make g++ git

# # Copy package files first for better caching
# COPY package*.json ./
# RUN npm install --legacy-peer-deps

# # Explicitly install baileys with legacy-peer-deps
# RUN npm install @whiskeysockets/baileys@latest --legacy-peer-deps

# # Copy configuration files
# COPY tsconfig.json rollup.config.js ./

# # Copy source code
# COPY src/ ./src/

# # Build with Rollup
# RUN npm run build

# # Create required directories
# RUN mkdir -p src/auth logs src/registeredVendors
# RUN echo "[]" > src/registeredVendors/vendors.json

# # Expose the port
# EXPOSE 3000

# # Start the application
# CMD ["npm", "start"]


