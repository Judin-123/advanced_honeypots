"""Run the application with debug settings"""
import os
import sys
import logging
from app import app

# Configure logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

if __name__ == '__main__':
    try:
        # Verify template directory exists
        template_dir = os.path.join(os.path.dirname(__file__), 'templates')
        if not os.path.exists(template_dir):
            logger.error(f"Template directory not found: {template_dir}")
            sys.exit(1)
            
        # List available templates
        logger.info("Available templates in %s:", template_dir)
        for f in os.listdir(template_dir):
            logger.info(f"- {f} (size: {os.path.getsize(os.path.join(template_dir, f))} bytes)")
            
        # Start the application
        logger.info("Starting application...")
        app.run(
            host='0.0.0.0',
            port=5000,
            debug=True,
            use_debugger=True,
            use_reloader=True,
            passthrough_errors=True
        )
    except Exception as e:
        logger.exception("Fatal error in application:")
        raise
