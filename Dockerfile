FROM node:20-alpine
WORKDIR /app
COPY package.json ./
RUN npm install --omit=dev
COPY server.js ./
COPY public ./public
COPY secure ./secure
EXPOSE 80
CMD ["node", "server.js"]
