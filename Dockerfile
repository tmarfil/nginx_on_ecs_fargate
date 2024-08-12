# Use the existing nginx image as the base
FROM <your-account-id>.dkr.ecr.$AWS_REGION.amazonaws.com/my-nginx-repo:r32

# Install necessary packages in a single layer
RUN apt-get update && \
    apt-get install -y awscli jq less wget vim && \
    apt-get clean

# Ensure the permissions are correct for the HTML file
COPY qs.html /usr/share/nginx/html/index.html
RUN chmod 644 /usr/share/nginx/html/index.html

# Copy a custom nginx configuration file
COPY nginx.conf /etc/nginx/nginx.conf

# Script to fetch TLS cert and key from AWS Secrets Manager
COPY fetch_and_setup_tls.sh /usr/local/bin/fetch_and_setup_tls.sh
RUN chmod +x /usr/local/bin/fetch_and_setup_tls.sh

# Expose HTTP, and HTTPS ports
EXPOSE 80 443

# Start NGINX
CMD /usr/local/bin/fetch_and_setup_tls.sh && nginx -g 'daemon off;'
