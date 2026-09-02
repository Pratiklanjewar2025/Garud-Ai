import logging
import traceback
from sqlalchemy.orm import Session
from androguard.core.bytecodes.apk import APK
from models import APKSample

logger = logging.getLogger("garud_ai.analyzer")


def analyze_apk_background(sample_id: str, file_path: str, SessionLocal):
    """
    Run APK analysis in a FastAPI BackgroundTask.

    IMPORTANT: We receive SessionLocal (the factory) — NOT the request-scoped db
    session from the route. The request-scoped session closes as soon as the HTTP
    response is sent, causing DetachedInstanceError if we try to use it here.
    We create our own session that we own and close ourselves.
    """
    db: Session = SessionLocal()
    try:
        sample = db.query(APKSample).filter(APKSample.sample_id == sample_id).first()
        if not sample:
            logger.warning(f"Sample not found for background analysis: {sample_id}")
            return

        logger.info(f"[{sample_id}] Starting APK analysis: {file_path}")
        sample.status = "ANALYZING"
        db.commit()

        # Parse APK using Androguard
        a = APK(file_path)

        # Extract metadata
        sample.package_name = a.get_package()
        sample.version_name = a.get_androidversion_name()
        sample.target_sdk = str(a.get_target_sdk_version())

        # Permissions
        sample.permissions = a.get_permissions()

        # Activities
        sample.activities = a.get_activities()

        # Services
        sample.services = a.get_services()

        sample.status = "COMPLETED"
        db.commit()
        logger.info(f"[{sample_id}] Analysis completed successfully.")

    except Exception as e:
        logger.error(f"[{sample_id}] Analysis failed: {e}\n{traceback.format_exc()}")
        try:
            sample = db.query(APKSample).filter(APKSample.sample_id == sample_id).first()
            if sample:
                sample.status = "FAILED"
                sample.error_message = str(e) + "\n" + traceback.format_exc()
                db.commit()
        except Exception as inner_e:
            logger.error(f"[{sample_id}] Failed to write error state: {inner_e}")
    finally:
        db.close()
