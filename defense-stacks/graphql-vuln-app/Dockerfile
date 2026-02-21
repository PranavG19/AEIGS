FROM node:20-alpine
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --production
COPY . .
EXPOSE 4000
HEALTHCHECK --interval=5s --timeout=3s --start-period=10s CMD node -e "const http=require('http');http.get('http://localhost:4000/health',r=>{process.exit(r.statusCode===200?0:1)}).on('error',()=>process.exit(1))"
CMD ["node", "app.js"]
