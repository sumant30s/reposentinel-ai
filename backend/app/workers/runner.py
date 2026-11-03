import logging
import os
import signal
import subprocess
import sys
import time

from app.core.config import get_settings
from app.core.logging import setup_logging
from app.models.database import sessions
from app.workers.jobs import claim_job, fail_job, recover_jobs


def main() -> None:
    setup_logging()
    settings = get_settings()
    factory = sessions(settings.database_url)
    while True:
        recover_jobs(settings)
        with factory() as session:
            scan_id = claim_job(session, settings.scan_timeout)
        if not scan_id:
            time.sleep(1)
            continue
        logging.info("scan_started id=%s", scan_id)
        process = subprocess.Popen(
            [sys.executable, "-m", "app.workers.execute", scan_id],
            start_new_session=os.name != "nt",
        )
        try:
            code = process.wait(timeout=settings.scan_timeout)
            if code:
                fail_job(settings, scan_id, "Scanner subprocess exited unexpectedly")
        except subprocess.TimeoutExpired:
            if os.name == "nt":
                subprocess.run(
                    ["taskkill", "/PID", str(process.pid), "/T", "/F"],
                    check=False,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
            else:
                os.killpg(process.pid, signal.SIGKILL)
            process.wait()
            fail_job(settings, scan_id, "Hard scan deadline exceeded")
        logging.info("scan_finished id=%s", scan_id)


if __name__ == "__main__":
    main()
