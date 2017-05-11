from readsync import db, app, settings
from readsync.models import User, Book, UserBook
from readsync.amazon_kindle.models import KindleSyncAccount
from readsync.utils import db as db_utils
from xml.dom import minidom
import oauth2 as oauth
from datetime import datetime
from celery.task import task, periodic_task

@periodic_task(run_every=settings.SYNC_INTERVAL)
def sync_all_users():
    """Sync all user's books with Kindle accounts"""
    for account in db.session.query(KindleSyncAccount).all():
        sync_user.delay(account.user.id)

@task
def sync_user(user_id):
    account = db.session.query(KindleSyncAccount).filter_by(user_id=user_id).one()
    if not account.active:
        print "Account for user %s not active" % user_id
    
    print "syncing amazon kindle user %s" % user_id
    # If the private key hasn't been converted yet, go ahead and do that now
    if not account.private_pem:
        print "converting private key"
        account.convert_pkcs8_to_pem()
    account.sync_request()    