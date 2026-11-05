FROM node:20-alpine AS builder
RUN npm ci
RUN npm run build

FROM nginx:1.25.3
COPY --from=builder /app/dist /usr/share/nginx/html
