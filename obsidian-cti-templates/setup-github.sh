#!/bin/bash

# GitHub Repository Setup Script
# For Obsidian CTI Templates

set -e

GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

print_info() { echo -e "${BLUE}ℹ ${NC}$1"; }
print_success() { echo -e "${GREEN}✓${NC} $1"; }
print_warning() { echo -e "${YELLOW}⚠${NC} $1"; }
print_error() { echo -e "${RED}✗${NC} $1"; }

echo ""
echo "╔════════════════════════════════════════════════════════════╗"
echo "║   Obsidian CTI Templates                                   ║"
echo "║   GitHub Repository Setup Script                           ║"
echo "╚════════════════════════════════════════════════════════════╝"
echo ""

if ! command -v git &> /dev/null; then
    print_error "Git is not installed. Please install Git first."
    exit 1
fi

print_success "Git is installed"

if [ ! -f "README.md" ]; then
    print_error "This script must be run from the obsidian-cti-templates directory"
    exit 1
fi

print_success "Running in correct directory"

echo ""
print_info "Setting up your GitHub repository..."
echo ""
read -p "Enter your GitHub username: " GITHUB_USERNAME

if [ -z "$GITHUB_USERNAME" ]; then
    print_error "GitHub username cannot be empty"
    exit 1
fi

read -p "Enter repository name [obsidian-cti-templates]: " REPO_NAME
REPO_NAME=${REPO_NAME:-obsidian-cti-templates}

echo ""
print_info "Repository visibility:"
echo "  1) Public (recommended for open source)"
echo "  2) Private"
read -p "Choose (1 or 2) [1]: " VISIBILITY_CHOICE
VISIBILITY_CHOICE=${VISIBILITY_CHOICE:-1}

if [ "$VISIBILITY_CHOICE" = "2" ]; then
    VISIBILITY="private"
else
    VISIBILITY="public"
fi

echo ""
print_warning "Repository Details:"
echo "  Username: $GITHUB_USERNAME"
echo "  Repository: $REPO_NAME"
echo "  Visibility: $VISIBILITY"
echo "  URL: https://github.com/$GITHUB_USERNAME/$REPO_NAME"
echo ""
read -p "Is this correct? (y/n) [y]: " CONFIRM
CONFIRM=${CONFIRM:-y}

if [ "$CONFIRM" != "y" ] && [ "$CONFIRM" != "Y" ]; then
    print_warning "Setup cancelled"
    exit 0
fi

echo ""
print_info "Initializing Git repository..."

if [ -d ".git" ]; then
    print_warning "Git repository already initialized"
else
    git init
    print_success "Git repository initialized"
fi

if [ -z "$(git config user.name)" ]; then
    read -p "Enter your name for git commits: " GIT_NAME
    git config user.name "$GIT_NAME"
fi

if [ -z "$(git config user.email)" ]; then
    read -p "Enter your email for git commits: " GIT_EMAIL
    git config user.email "$GIT_EMAIL"
fi

print_info "Adding files to git..."
git add .
print_success "Files added"

print_info "Creating initial commit..."
git commit -m "Initial release v1.0.0 - Obsidian CTI Templates

- 11 professional threat intelligence templates
- Comprehensive documentation
- Quick start guide
- MITRE ATT&CK integration
- IOC tracking templates
- Detection rule formats
- MIT License"
print_success "Initial commit created"

print_info "Setting default branch to 'main'..."
git branch -M main
print_success "Branch set to main"

print_info "Adding GitHub remote..."
REPO_URL="https://github.com/$GITHUB_USERNAME/$REPO_NAME.git"
git remote add origin "$REPO_URL" 2>/dev/null || git remote set-url origin "$REPO_URL"
print_success "Remote added: $REPO_URL"

echo ""
echo "╔════════════════════════════════════════════════════════════╗"
echo "║   NEXT STEPS                                               ║"
echo "╚════════════════════════════════════════════════════════════╝"
echo ""
print_info "Now you need to create the repository on GitHub:"
echo ""
echo "  1. Go to: https://github.com/new"
echo ""
echo "  2. Fill in the following:"
echo "     Repository name: $REPO_NAME"
echo "     Description: Professional Obsidian templates for cyber threat intelligence analysts"
echo "     Visibility: $VISIBILITY"
echo "     ⚠ DO NOT initialize with README, .gitignore, or license"
echo ""
echo "  3. Click 'Create repository'"
echo ""
read -p "Press Enter when you've created the repository on GitHub..."

echo ""
print_info "Pushing to GitHub..."
echo ""

if git push -u origin main; then
    echo ""
    print_success "Successfully pushed to GitHub!"
    echo ""
    echo "╔════════════════════════════════════════════════════════════╗"
    echo "║   SUCCESS! 🎉                                             ║"
    echo "╚════════════════════════════════════════════════════════════╝"
    echo ""
    print_success "Your repository is now live at:"
    echo "  https://github.com/$GITHUB_USERNAME/$REPO_NAME"
    echo ""
    print_info "Recommended next steps:"
    echo ""
    echo "  1. Add repository topics (on GitHub):"
    echo "     obsidian, threat-intelligence, cybersecurity, cti, security"
    echo "     mitre-attack, ioc, malware-analysis, apt"
    echo ""
    echo "  2. Create a release:"
    echo "     - Go to: https://github.com/$GITHUB_USERNAME/$REPO_NAME/releases/new"
    echo "     - Tag: v1.0.0"
    echo "     - Title: Initial Release - Obsidian CTI Templates"
    echo ""
    echo "  3. Share your repository!"
    echo ""
else
    print_error "Failed to push to GitHub"
    echo ""
    print_info "To retry pushing manually, run:"
    echo "    git push -u origin main"
    echo ""
    exit 1
fi

echo ""
