# node:18-bullseye — full Debian base, introduces OS-level CVEs for demo scanning
FROM node:18-bullseye

WORKDIR /app

COPY package*.json ./
RUN npm install --omit=dev

COPY . .

EXPOSE 3000

CMD ["node", "app.js"]
