FROM node:24-alpine

WORKDIR /app
COPY frontend/siem-dashboard/package*.json ./
RUN npm install
COPY frontend/siem-dashboard .
EXPOSE 5173
CMD ["npm", "run", "dev", "--", "--host", "0.0.0.0"]
