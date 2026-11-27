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
# WeasyPrint, which prints the incident report to PDF, draws its text with
# the Pango library. Pango is not a Python package, so pip cannot install it
# and it is added here. DejaVu is a spare font for any character the
# report's own font does not have.
RUN apt-get update     && apt-get install -y --no-install-recommends         libpango-1.0-0 libpangoft2-1.0-0 libharfbuzz-subset0 fonts-dejavu-core     && rm -rf /var/lib/apt/lists/*
COPY backend/requirements.txt backend/requirements.txt
RUN pip install --no-cache-dir -r backend/requirements.txt
COPY backend/ backend/
COPY --from=frontend /app/frontend/dist frontend/dist
# The report is set in the same typeface as the app. The font files are
# taken from the frontend's packages, so both always use the same version.
COPY --from=frontend     /app/frontend/node_modules/@fontsource/ibm-plex-sans/files/ibm-plex-sans-latin-400-normal.woff2     /app/frontend/node_modules/@fontsource/ibm-plex-sans/files/ibm-plex-sans-latin-500-normal.woff2     /app/frontend/node_modules/@fontsource/ibm-plex-sans/files/ibm-plex-sans-latin-600-normal.woff2     /app/frontend/node_modules/@fontsource/ibm-plex-mono/files/ibm-plex-mono-latin-400-normal.woff2     backend/reports/fonts/

# Run as an ordinary user, not root, so a bug in the app has less power.
RUN useradd --create-home sentinel && mkdir /data && chown sentinel /data
USER sentinel

ENV SENTINEL_DB=/data/sentinel.db
EXPOSE 8000
CMD ["uvicorn", "backend.main:app", "--host", "0.0.0.0", "--port", "8000"]
