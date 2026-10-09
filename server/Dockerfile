FROM node:22-alpine
WORKDIR /app
COPY package*.json ./
RUN npm ci --omit=dev
COPY src ./src
COPY scripts ./scripts
EXPOSE 5000
ENV NODE_ENV=production
CMD ["node","src/server.js"]
