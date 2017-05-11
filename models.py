from readsync import db, app
from readsync.models import Book, UserBook
import sqlalchemy
import urllib
import httplib
import hashlib
import base64
import uuid
from lxml import etree
import subprocess
from datetime import datetime
from tempfile import NamedTemporaryFile
from M2Crypto import RSA
from readsync.utils import db as db_utils


def generate_device_serialno():
    """ Generates a valid 40-digit hex serialno (sha1) """
    return hashlib.sha1(uuid.uuid4().hex).hexdigest()

class WisperClientError(Exception):
    msg = ""

    def __init__(self, msg):
        self.msg = msg

class AuthenticationError(WisperClientError):
    pass

class KindleSyncAccount(db.Model):
    """ Amazon Kindle account information """
    __tablename__ = "kindle_accounts"
    __table_args__ = ( None, { 'mysql_engine': 'InnoDB',
        'mysql_charset': 'utf8' } )
        
    FIRS_SERVER = 'firs-ta-g7g.amazon.com'
    TODO_SERVER = 'todo-ta-g7g.amazon.com'
        
    user_id = db.Column('user_id', db.BigInteger, db.ForeignKey('users.id'),
        primary_key=True)
    user = db.relationship("User", backref="kindle_assoc")
    added = db.Column(db.DateTime, default=datetime.now)
    updated = db.Column(db.DateTime, default=datetime.now)
    device_serialno = db.Column(db.String(40),
        default=lambda: generate_device_serialno())
    last_sync = db.Column(db.String(30), nullable=True)
    private_key = db.Column(db.Text())
    private_pem = db.Column(db.Text())
    adp_token = db.Column(db.Text())
    active = db.Column(db.Boolean, default=False)
    
    def sync_request(self, force_full_sync=False):
        #TODO support partial sync
        path = "/FionaTodoListProxy/syncMetaData"
        headers = {
            "Host": self.TODO_SERVER,
            "User-Agent": "Dalvik/1.2.0",
            "x-adp-authentication-token": self.adp_token ,
            "x-adp-request-digest": self.header_digest("GET", path),
        }
        if (not force_full_sync) and self.last_sync:
            path = "%s?last_sync_time=%s" % (path, time)

        conn = httplib.HTTPSConnection(self.TODO_SERVER, 443)
        conn.request("GET", path, headers=headers)
        response = conn.getresponse()
        if response.status != 200:
            raise WisperClientError('[%d] Sync Error' % response.status)
        doc = response.read()
#        print doc
        root = etree.fromstring(doc)
        sync_time = root.find('sync_time').text.split(";")[0]
        sync_type = root.attrib['syncType']

        add = root.find('add_update_list')
        def gettext(element, key, default=""):
            value = element.find(key)
            if value is None:
                return default
            return value.text

        for book in add.findall('meta_data'):
            asin = book.find("ASIN").text
            title = gettext(book, 'title')
            #TODO: support multiple authors
            author = gettext(book, 'authors/author')
            publisher = gettext(book, 'publisher')
            pub_date = gettext(book, 'publication_date', None)
            if pub_date:
                pub_date = datetime.strptime(pub_date, '%Y-%m-%dT%H:%M:%S+0000')
            book_obj, created = db_utils.get_or_create(Book, asin=asin)
            if created:
                book_obj.title = title
                book_obj.author = author
                book_obj.publisher = publisher
                book_obj.pub_date = pub_date
            user_book, created = db_utils.get_or_create(UserBook,
                book=book_obj, user=self.user)
            db.session.commit()
        remove = root.find('removal_list')
        for book in remove.findall('meta_data'):
            asin = book.find("ASIN").text
            # TODO remove user book

    def convert_pkcs8_to_pem(self):
        """ Blocking process that calls subprocess to invoke openssl which 
            converts the private key to something useable by M2Crypto
        """
        infile = NamedTemporaryFile()
        infile.write(base64.b64decode(self.private_key))
        infile.flush()
        outfile = NamedTemporaryFile(mode='r')
        # openssl pkcs8 -in derkey -inform der -outform pem -nocrypt
        subprocess.call(['openssl', 'pkcs8', '-in', infile.name,
            '-inform', 'der', '-outform', 'pem', '-out', outfile.name,
            '-nocrypt'])
        self.private_pem = outfile.read()
        db.session.commit()
        infile.close() # deletes the temp file
        outfile.close()

    def header_digest(self, method, url, postdata="",
        time=datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")):
        """Returns a digest header for use in sync reqeusts"""
        data = "%s\n%s\n%s\n%s\n%s" % \
            (method, url, time, postdata, self.adp_token)  
        rsa = RSA.load_key_string(str(self.private_pem))
        crypt = rsa.private_encrypt(hashlib.sha256(data).digest(),
            RSA.pkcs1_padding)
        sig = base64.b64encode(crypt)
        return "%s:%s" % (sig, time)

    def parse_auth_response(self, xmlstr):
        """ Parses a xml auth response into a python dict """
        root = etree.fromstring(xmlstr)
        login_fail = root.find('customer_not_found')
        if login_fail != None:
            raise AuthenticationError('Invalid Username or password')
        if root.tag == "error":
            raise WisperClientError('Unknown Error')
        # print xmlstr
        self.adp_token = root.find('adp_token').text
        self.private_key = root.find('device_private_key').text
        self.active = True
        db.session.commit()

    def authenticate(self, email, password):
        params = urllib.urlencode({"email": email, "password": password})
        headers = {
            "content-type": "application/x-www-form-urlencoded",
            "content-length": len(params),
            "Host": self.FIRS_SERVER,
            "User-Agent": "Dalvik/1.2.0",
            "Connection": "Keep-Alive"
        }
        urlparams = urllib.urlencode( {
            "deviceType": "A3VNNDO1I14V03",
            "deviceSerialNumber": self.device_serialno,
            "deviceName": "%FIRST_NAME%'s %DUPE_STRATEGY_1ST% ReadSync Client",
            "pid": "9D184DE1",
            "certFormat": "B64/PKCS#8",
            "softwareVersion": "81170056",
            "os_version": "2.2",
            "device_model": "Nexus One HTTP/1.1"
        })
        conn = httplib.HTTPSConnection(self.FIRS_SERVER, 443)
        conn.request("POST", "/FirsProxy/registerDevice?%s" % urlparams, params, headers)
        response = conn.getresponse()
        if response.status != 200:
            raise WisperClientError('Unknown Error')
        # print response.status, response.reason
        data = response.read()
        conn.close()
        self.parse_auth_response(data)
        return True