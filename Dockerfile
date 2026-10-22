FROM node:20-alpine AS dependencies
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci

FROM dependencies AS development
COPY . .
CMD ["npm", "run", "dev:web"]

FROM dependencies AS build
COPY . .
RUN npm run build

FROM node:20-alpine AS runtime
ENV NODE_ENV=production
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --omit=dev
COPY scripts/migrate.ts ./scripts/migrate.ts
COPY db/migrations ./db/migrations
COPY --from=build /app/dist ./dist
EXPOSE 3000
CMD ["sh", "-c", "npm run db:migrate && exec npm start"]
