import sys
import uuid

from app.core.config import get_settings
from app.workers.jobs import execute_job

if __name__ == "__main__":
    settings = get_settings()
    try:
        import resource

        resource.setrlimit(resource.RLIMIT_FSIZE, (16 * 1024 * 1024, 16 * 1024 * 1024))
        resource.setrlimit(resource.RLIMIT_NOFILE, (256, 256))
        resource.setrlimit(resource.RLIMIT_CPU, (settings.scan_timeout, settings.scan_timeout))
    except ImportError:
        pass  # Windows uses parent deadline and process-tree termination.
    execute_job(settings, str(uuid.UUID(sys.argv[1])))
