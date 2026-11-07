FROM node:24-slim AS build

WORKDIR /app

COPY package.json package-lock.json ./
RUN npm install --global npm@11.16.0 && npm ci

COPY tsconfig.json tsconfig.build.json ./
COPY src ./src

RUN npm run build

FROM node:24-slim AS runtime

WORKDIR /app
ENV NODE_ENV=production

COPY package.json package-lock.json ./
RUN npm install --global npm@11.16.0 && npm ci --omit=dev

COPY --from=build /app/dist ./dist

RUN mkdir -p /app/data

EXPOSE 8080
CMD ["node", "dist/index.js"]

