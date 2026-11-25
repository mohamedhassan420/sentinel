# One image that serves both the API and the built frontend.

# Stage 1: turn the React source into plain HTML, CSS and JavaScript files.
FROM node:24-alpine AS frontend
WORKDIR /app/frontend
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci
COPY frontend/ ./
RUN npm run build

# Stage 2: the Python backend. Node is left behind in stage 1; only the
# built files are copied across, which keeps the final image small.
FROM python:3.12-slim
WORKDIR /app
COPY backend/requirements.txt backend/requirements.txt
RUN pip install --no-cache-dir -r backend/requirements.txt
COPY backend/ backend/
COPY --from=frontend /app/frontend/dist frontend/dist

# Run as an ordinary user, not root, so a bug in the app has less power.
RUN useradd --create-home sentinel && mkdir /data && chown sentinel /data
USER sentinel

ENV SENTINEL_DB=/data/sentinel.db
EXPOSE 8000
CMD ["uvicorn", "backend.main:app", "--host", "0.0.0.0", "--port", "8000"]
