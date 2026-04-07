FROM node:20-alpine

WORKDIR /app

COPY package.json package-lock.json* ./
RUN npm install --production

COPY server.js .
COPY public/ public/
RUN mkdir -p data

# Mount data/ as a volume for RSVP persistence across restarts:
#   docker run -v $(pwd)/data:/app/data ...
VOLUME ["/app/data"]

EXPOSE 3847

ENV PORT=3847
ENV TZ=America/Argentina/Buenos_Aires

CMD ["node", "server.js"]
