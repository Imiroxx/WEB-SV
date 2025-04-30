import os
import ssl
import requests
import logging
from pathlib import Path


def setup_ssl_certificate():
    logging.basicConfig(
        filename='logs/ssl_setup.log',
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s'
    )
    logger = logging.getLogger(__name__)
    cert_dir = Path.home() / '.mysql'
    cert_path = cert_dir / 'root.crt'
    try:
        cert_dir.mkdir(parents=True, exist_ok=True)
        logger.info(f"Certificate directory: {cert_dir}")
        if cert_path.exists():
            logger.info("SSL certificate already exists")
            return True
        url = "https://storage.yandexcloud.net/cloud-certs-public/CA.pem"
        response = requests.get(url)
        response.raise_for_status()
        with open(cert_path, 'wb') as f:
            f.write(response.content)
        logger.info("SSL certificate downloaded successfully")
        return True
    except Exception as e:
        logger.error(f"Error setting up SSL certificate: {e}")
        return False


if __name__ == '__main__':
    if setup_ssl_certificate():
        print("SSL certificate setup completed successfully")
    else:
        print("Failed to setup SSL certificate. Check logs for details.")
