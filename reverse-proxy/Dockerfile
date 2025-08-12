FROM haproxy:2.8-alpine

# Switch to root user
USER root

# Install required packages for Lua and JWT validation
RUN apk update && apk add --no-cache \
    lua5.3 \
    lua5.3-cjson \
    lua5.3-socket \
    lua5.3-http \
    curl \
    envsubst

# Copy configuration files
COPY haproxy.cfg /usr/local/etc/haproxy/haproxy.cfg.template
COPY jwt_validate.lua /usr/local/etc/haproxy/jwt_validate.lua

# Fix permissions for haproxy user
RUN chown -R haproxy:haproxy /usr/local/etc/haproxy

# Create startup script
RUN echo '#!/bin/sh' > /usr/local/bin/start-haproxy.sh && \
    echo 'set -e' >> /usr/local/bin/start-haproxy.sh && \
    echo '' >> /usr/local/bin/start-haproxy.sh && \
    echo '# Substitute environment variables in HAProxy config' >> /usr/local/bin/start-haproxy.sh && \
    echo 'envsubst < /usr/local/etc/haproxy/haproxy.cfg.template > /usr/local/etc/haproxy/haproxy.cfg' >> /usr/local/bin/start-haproxy.sh && \
    echo '' >> /usr/local/bin/start-haproxy.sh && \
    echo '# Validate HAProxy configuration' >> /usr/local/bin/start-haproxy.sh && \
    echo 'haproxy -c -f /usr/local/etc/haproxy/haproxy.cfg' >> /usr/local/bin/start-haproxy.sh && \
    echo '' >> /usr/local/bin/start-haproxy.sh && \
    echo '# Start HAProxy' >> /usr/local/bin/start-haproxy.sh && \
    echo 'exec haproxy -f /usr/local/etc/haproxy/haproxy.cfg' >> /usr/local/bin/start-haproxy.sh && \
    chmod +x /usr/local/bin/start-haproxy.sh

# Expose ports
EXPOSE 80 8404

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD haproxy -c -f /usr/local/etc/haproxy/haproxy.cfg || exit 1

# Switch to haproxy user
USER haproxy

# Start HAProxy with environment variable substitution
CMD ["/usr/local/bin/start-haproxy.sh"] 