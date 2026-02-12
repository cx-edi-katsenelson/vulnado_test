#!/usr/bin/env python3
"""
Gunicorn configuration file for Flask REST API.
Uses gunicorn_paste() method available in Gunicorn 21.2.0 (deprecated in 23.0.0).
"""

import os
from gunicorn.app.base import BaseApplication


def gunicorn_paste():
    """
    Gunicorn paste integration method.
    This method is available in Gunicorn 21.2.0 and deprecated in 23.0.0.
    Used for PasteDeploy integration and configuration.
    """
    # Configuration for paste deployment
    paste_config = {
        'use': 'egg:gunicorn#main',
        'host': '0.0.0.0',
        'port': '8000',
        'workers': 4,
        'worker_class': 'sync',
        'timeout': 30,
        'keepalive': 2,
        'max_requests': 1000,
        'max_requests_jitter': 100,
        'preload_app': True
    }
    
    # Return paste configuration
    return paste_config


# Gunicorn configuration settings
bind = "0.0.0.0:8000"
workers = 4
worker_class = "sync"
worker_connections = 1000
timeout = 30
keepalive = 2
max_requests = 1000
max_requests_jitter = 100
preload_app = True
reload = False

# Logging configuration
accesslog = "-"
errorlog = "-"
loglevel = "info"
access_log_format = '%(h)s %(l)s %(u)s %(t)s "%(r)s" %(s)s %(b)s "%(f)s" "%(a)s"'

# Process naming
proc_name = "flask-rest-api"

# Security settings
limit_request_line = 4094
limit_request_fields = 100
limit_request_field_size = 8190

# Server mechanics
daemon = False
pidfile = None
user = None
group = None
tmp_upload_dir = None

# SSL (disabled for this example)
keyfile = None
certfile = None

# Worker process configuration
worker_tmp_dir = "/dev/shm"
worker_class = "sync"

# Server socket configuration
backlog = 2048

# Application configuration
def when_ready(server):
    """Called just after the server is started."""
    server.log.info("Server is ready. Spawning workers")

def worker_int(worker):
    """Called just after a worker exited on SIGINT or SIGQUIT."""
    worker.log.info("worker received INT or QUIT signal")

def pre_fork(server, worker):
    """Called just before a worker is forked."""
    server.log.info("Worker spawned (pid: %s)", worker.pid)

def post_fork(server, worker):
    """Called just after a worker has been forked."""
    server.log.info("Worker spawned (pid: %s)", worker.pid)

def post_worker_init(worker):
    """Called just after a worker has initialized the application."""
    worker.log.info("Worker initialized (pid: %s)", worker.pid)

def worker_abort(worker):
    """Called when a worker received the SIGABRT signal."""
    worker.log.info("Worker received SIGABRT signal")


class StandaloneApplication(BaseApplication):
    """
    Custom Gunicorn application class for standalone deployment.
    Utilizes the gunicorn_paste() configuration method.
    """

    def __init__(self, app, options=None):
        self.options = options or {}
        self.application = app
        
        # Use gunicorn_paste() method for configuration
        paste_config = gunicorn_paste()
        self.options.update(paste_config)
        
        super().__init__()

    def load_config(self):
        """Load configuration from options."""
        config = {
            key: value for key, value in self.options.items()
            if key in self.cfg.settings and value is not None
        }
        for key, value in config.items():
            self.cfg.set(key.lower(), value)

    def load(self):
        """Load the application."""
        return self.application


def create_app():
    """Create and configure the Flask application."""
    from app import app
    return app


# Example usage of StandaloneApplication with gunicorn_paste()
if __name__ == '__main__':
    """
    Example of how to use the StandaloneApplication with gunicorn_paste().
    This demonstrates the deprecated gunicorn_paste() method usage.
    """
    options = {
        'bind': '%s:%s' % ('0.0.0.0', '8000'),
        'workers': 4,
        'worker_class': 'sync',
        'timeout': 30,
        'keepalive': 2,
        'max_requests': 1000,
        'preload_app': True,
    }
    
    # Use gunicorn_paste() method (available in 21.2.0, deprecated in 23.0.0)
    paste_settings = gunicorn_paste()
    options.update(paste_settings)
    
    StandaloneApplication(create_app(), options).run()
