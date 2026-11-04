#!/usr/bin/env bash
# Build script for Render. Exit on the first error.
set -o errexit

pip install -r requirements.txt
python manage.py collectstatic --no-input
python manage.py migrate

# Create the admin user from environment variables (skip quietly if it already exists).
python manage.py createsuperuser --noinput || echo "Admin user already exists, skipping."
