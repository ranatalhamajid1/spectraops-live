#!/bin/bash

# SpectraOps Deployment Script
# This script handles the complete deployment process

set -e  # Exit on any error

echo "🚀 Starting SpectraOps Deployment..."

# Configuration
DOMAIN="spectraops.com"
REPO_URL="https://github.com/spectraops/website.git"
DEPLOY_PATH="/var/www/spectraops"
BACKUP_PATH="/var/backups/spectraops"
NGINX_CONFIG="/etc/nginx/sites-available/spectraops"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if running as root
if [[ $EUID -eq 0 ]]; then
   print_error "This script should not be run as root for security reasons"
   exit 1
fi

# Check prerequisites
check_prerequisites() {
    print_status "Checking prerequisites..."
    
    # Check if Node.js is installed
    if ! command -v node &> /dev/null; then
        print_error "Node.js is not installed. Please install Node.js 16 or higher."
        exit 1
    fi
    
    # Check Node.js version
    NODE_VERSION=$(node --version | cut -d'v' -f2 | cut -d'.' -f1)
    if [ "$NODE_VERSION" -lt 16 ]; then
        print_error "Node.js version 16 or higher is required. Current version: $(node --version)"
        exit 1
    fi
    
    # Check if npm is installed
    if ! command -v npm &> /dev/null; then
        print_error "npm is not installed"
        exit 1
    fi
    
    # Check if PM2 is installed
    if ! command -v pm2 &> /dev/null; then
        print_warning "PM2 is not installed. Installing PM2..."
        npm install -g pm2
    fi
    
    # Check if Docker is installed
    if ! command -v docker &> /dev/null; then
        print_warning "Docker is not installed. Some features may not work."
    fi
    
    print_status "Prerequisites check completed ✅"
}

# Create backup
create_backup() {
    print_status "Creating backup..."
    
    if [ -d "$DEPLOY_PATH" ]; then
        BACKUP_NAME="spectraops-backup-$(date +%Y%m%d-%H%M%S)"
        sudo mkdir -p "$BACKUP_PATH"
        sudo cp -r "$DEPLOY_PATH" "$BACKUP_PATH/$BACKUP_NAME"
        print_status "Backup created: $BACKUP_PATH/$BACKUP_NAME"
    else
        print_status "No existing deployment found, skipping backup"
    fi
}

# Setup deployment directory
setup_deployment() {
    print_status "Setting up deployment directory..."
    
    # Create deployment directory
    sudo mkdir -p "$DEPLOY_PATH"
    sudo chown $USER:$USER "$DEPLOY_PATH"
    
    # Clone or update repository
    if [ -d "$DEPLOY_PATH/.git" ]; then
        print_status "Updating existing repository..."
        cd "$DEPLOY_PATH"
        git fetch origin
        git reset --hard origin/main
    else
        print_status "Cloning repository..."
        git clone "$REPO_URL" "$DEPLOY_PATH"
        cd "$DEPLOY_PATH"
    fi
}

# Install dependencies
install_dependencies() {
    print_status "Installing backend dependencies..."
    cd "$DEPLOY_PATH/backend"
    npm ci --production
    
    print_status "Building frontend..."
    cd "$DEPLOY_PATH/frontend"
    # If using a build process, add it here
    # npm run build
}

# Setup database
setup_database() {
    print_status "Setting up database..."
    cd "$DEPLOY_PATH/backend"
    
    # Create data directory
    mkdir -p data
    
    # Initialize database if it doesn't exist
    if [ ! -f "data/spectraops.db" ]; then
        print_status "Initializing new database..."
        npm run init-db
    else
        print_status "Database already exists, running migrations..."
        # Add migration script if needed
        # npm run migrate
    fi
}

# Configure environment
configure_environment() {
    print_status "Configuring environment..."
    cd "$DEPLOY_PATH/backend"
    
    # Copy environment template if .env doesn't exist
    if [ ! -f ".env" ]; then
        if [ -f ".env.example" ]; then
            cp .env.example .env
            print_warning "Environment file created from template. Please update with your settings."
        else
            print_error "No .env.example file found"
            exit 1
        fi
    fi
    
    # Generate JWT secret if not set
    if ! grep -q "JWT_SECRET=" .env || grep -q "JWT_SECRET=your-super-secret" .env; then
        JWT_SECRET=$(openssl rand -base64 32)
        sed -i "s/JWT_SECRET=.*/JWT_SECRET=$JWT_SECRET/" .env
        print_status "Generated new JWT secret"
    fi
    
    # Set production environment
    sed -i "s/NODE_ENV=.*/NODE_ENV=production/" .env
    sed -i "s/DOMAIN=.*/DOMAIN=$DOMAIN/" .env
}

# Setup SSL certificates
setup_ssl() {
    print_status "Setting up SSL certificates..."
    cd "$DEPLOY_PATH/backend"
    
    # Create SSL directory
    mkdir -p ssl
    
    # Setup Let's Encrypt if certificates don't exist
    if [ ! -f "ssl/certificate.crt" ]; then
        print_status "Setting up Let's Encrypt SSL certificates..."
        node deployment/ssl-setup.js
    else
        print_status "SSL certificates already exist"
    fi
}

# Configure Nginx
configure_nginx() {
    print_status "Configuring Nginx..."
    
    # Create Nginx configuration
    sudo tee "$NGINX_CONFIG" > /dev/null <<EOF
server {
    listen 80;
    server_name $DOMAIN www.$DOMAIN;
    return 301 https://\$server_name\$request_uri;
}

server {
    listen 443 ssl http2;
    server_name $DOMAIN www.$DOMAIN;

    ssl_certificate $DEPLOY_PATH/backend/ssl/certificate.crt;
    ssl_certificate_key $DEPLOY_PATH/backend/ssl/private.key;
    
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-RSA-AES256-GCM-SHA512:DHE-RSA-AES256-GCM-SHA512:ECDHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES256-GCM-SHA384;
    ssl_prefer_server_ciphers off;
    ssl_session_cache shared:SSL:10m;
    
    # Security headers
    add_header X-Frame-Options DENY;
    add_header X-Content-Type-Options nosniff;
    add_header X-XSS-Protection "1; mode=block";
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload";

    # Frontend
    location / {
        root $DEPLOY_PATH/frontend;
        try_files \$uri \$uri/ /index.html;
        
        # Cache static assets
        location ~* \.(js|css|png|jpg|jpeg|gif|ico|svg|woff|woff2|ttf|eot)$ {
            expires 1y;
            add_header Cache-Control "public, immutable";
        }
    }

    # API Backend
    location /api/ {
        proxy_pass http://localhost:3000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_cache_bypass \$http_upgrade;
    }

    # Admin panel
    location /admin {
        proxy_pass http://localhost:3000;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
    }
}
EOF

    # Enable site
    sudo ln -sf "$NGINX_CONFIG" /etc/nginx/sites-enabled/
    
    # Test Nginx configuration
    sudo nginx -t
    
    # Reload Nginx
    sudo systemctl reload nginx
    print_status "Nginx configured and reloaded"
}

# Start application with PM2
start_application() {
    print_status "Starting application with PM2..."
    cd "$DEPLOY_PATH/backend"
    
    # Stop existing PM2 processes
    pm2 stop spectraops-backend 2>/dev/null || true
    pm2 delete spectraops-backend 2>/dev/null || true
    
    # Start application
    pm2 start ecosystem.config.js
    
    # Save PM2 configuration
    pm2 save
    
    # Setup PM2 startup script
    pm2 startup | grep "sudo" | bash || true
    
    print_status "Application started with PM2"
}

# Setup monitoring
setup_monitoring() {
    print_status "Setting up monitoring..."
    cd "$DEPLOY_PATH/backend"
    
    # Start monitoring service
    pm2 start scripts/monitor.js --name "spectraops-monitor"
    
    # Setup log rotation
    pm2 install pm2-logrotate
    pm2 set pm2-logrotate:max_size 10M
    pm2 set pm2-logrotate:retain 30
    
    print_status "Monitoring configured"
}

# Verify deployment
verify_deployment() {
    print_status "Verifying deployment..."
    
    # Check if application is running
    if pm2 show spectraops-backend > /dev/null 2>&1; then
        print_status "✅ Application is running"
    else
        print_error "❌ Application is not running"
        exit 1
    fi
    
    # Check if Nginx is serving the site
    if curl -f -s "https://$DOMAIN" > /dev/null; then
        print_status "✅ Website is accessible"
    else
        print_warning "⚠️ Website may not be accessible yet"
    fi
    
    # Check API health
    if curl -f -s "https://$DOMAIN/api/health" > /dev/null; then
        print_status "✅ API is responding"
    else
        print_warning "⚠️ API may not be responding yet"
    fi
}

# Cleanup function
cleanup() {
    print_status "Performing cleanup..."
    
    # Remove old backups (keep last 5)
    if [ -d "$BACKUP_PATH" ]; then
        cd "$BACKUP_PATH"
        ls -t | tail -n +6 | xargs rm -rf 2>/dev/null || true
    fi
    
    # Clean npm cache
    npm cache clean --force 2>/dev/null || true
    
    print_status "Cleanup completed"
}

# Main deployment function
main() {
    print_status "🚀 Starting SpectraOps deployment for $DOMAIN"
    
    check_prerequisites
    create_backup
    setup_deployment
    install_dependencies
    setup_database
    configure_environment
    setup_ssl
    configure_nginx
    start_application
    setup_monitoring
    verify_deployment
    cleanup
    
    print_status "🎉 Deployment completed successfully!"
    print_status "Website: https://$DOMAIN"
    print_status "Admin: https://$DOMAIN/admin"
    print_status "API: https://$DOMAIN/api"
    
    print_warning "Don't forget to:"
    print_warning "1. Update your .env file with proper credentials"
    print_warning "2. Configure your DNS to point to this server"
    print_warning "3. Set up regular backups"
    print_warning "4. Configure monitoring alerts"
}

# Error handling
trap 'print_error "Deployment failed at line $LINENO"' ERR

# Run main function
main "$@"