# Copyright (c) 2014 QuarksLab.
# This file is part of IRMA project.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License in the top-level directory
# of this distribution and at:
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# No part of the project, including this file, may be copied,
# modified, propagated, or distributed except according to the
# terms contained in the LICENSE file.
import hashlib
import os

from sqlalchemy import Table, Column, Integer, ForeignKey, String, \
    event
from sqlalchemy.engine import Engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship, backref
from sqlalchemy.orm.exc import NoResultFound, MultipleResultsFound

import config.parser as config
from lib.irma.common.exceptions import IrmaDatabaseResultNotFound, \
    IrmaDatabaseError, IrmaCoreError, IrmaValueError
from lib.common import compat
from lib.common.utils import UUID
from lib.irma.common.exceptions import IrmaFileSystemError
from lib.irma.common.utils import IrmaScanStatus
from lib.irma.database.sqlhandler import SQLDatabase
from lib.irma.database.sqlobjects import SQLDatabaseObject


def sql_db_connect():
    """Connection to DB
    """
    uri_params = config.get_sql_db_uri_params()
    # TODO args* style argument
    SQLDatabase.connect(uri_params[0], uri_params[1], uri_params[2],
                        uri_params[3], uri_params[4], uri_params[5])


# SQLite fix for ForeignKey support
# see http://docs.sqlalchemy.org/en/latest/dialects/sqlite.html
if config.get_sql_db_uri_params()[0] == 'sqlite':
    @event.listens_for(Engine, "connect")
    def set_sqlite_pragma(dbapi_connection, connection_record):
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()

    # Auto-create directory for sqlite db
    dirname = os.path.dirname(config.get_sql_db_uri_params()[5])
    dirname = os.path.abspath(dirname)
    if not os.path.exists(dirname):
        print("SQL directory does not exist {0}"
              "..creating".format(dirname))
        os.makedirs(dirname)
        os.chmod(dirname, 0777)
    elif not (os.path.isdir(dirname)):
        print("Error. SQL directory is a not a dir {0}"
              "".format(dirname))
        raise IrmaDatabaseError("Can not create Frontend database dir")

    db_name = os.path.abspath(config.get_sql_db_uri_params()[5])
    if not os.path.exists(db_name):
        # touch like method to create a rw-rw-rw- file for db
        open(db_name, 'a').close()
        os.chmod(db_name, 0666)


sql_db_connect()
Base = declarative_base()
tables_prefix = '{0}_'.format(config.get_sql_db_tables_prefix())

# Many to many Tag <-> File
tag_file = Table(
    '{0}tag_file'.format(tables_prefix),
    Base.metadata,
    Column(
        'id_tag',
        Integer,
        ForeignKey('{0}tag.id'.format(tables_prefix))
    ),
    Column(
        'id_file',
        Integer,
        ForeignKey('{0}file.id'.format(tables_prefix)))
)

# Many to many ProbeResult <-> FileWeb
probe_result_file_web = Table(
    '{0}probeResult_fileWeb'.format(tables_prefix),
    Base.metadata,
    Column(
        'id_fw',
        Integer,
        # see FileWeb.id_file
        ForeignKey('{0}fileWeb.id'.format(tables_prefix))
    ),
    # Removed from FileWeb FK due to SQLite limitation, conceptually it
    # should be a PKF in FileWeb
    # https://groups.google.com/forum/#!topic/sqlalchemy/TxISzgW7xUg
    # Column(
    #     'id_file',
    #     Integer
    # ),
    Column(
        'id_pr',
        Integer,
        ForeignKey('{0}probeResult.id'.format(tables_prefix))
    ),
    # See FileWeb
    # ForeignKeyConstraint(   # Composite PFK from FileWeb
    #     ['id_fw', 'id_file'],
    #     [
    #         '{0}fileWeb.id_fw'.format(tables_prefix),
    #         '{0}fileWeb.id_file'.format(tables_prefix)
    #     ]
    # )
)


class Tag(Base, SQLDatabaseObject):
    __tablename__ = '{0}tag'.format(tables_prefix)

    # SQLite fix for auto increment on ids
    # see http://docs.sqlalchemy.org/en/latest/dialects/sqlite.html
    if config.get_sql_db_uri_params()[0] == 'sqlite':
        __table_args__ = {'sqlite_autoincrement': True}

    # Fields
    id = Column(
        Integer,
        autoincrement=True,
        nullable=False,
        primary_key=True,
        name='id'
    )
    name = Column(
        String,
        nullable=False,
        name='name'
    )

    def __init__(self, name=''):
        super(Tag, self).__init__()
        self.name = name


class File(Base, SQLDatabaseObject):
    __tablename__ = '{0}file'.format(tables_prefix)

    # SQLite fix for auto increment on ids
    # see http://docs.sqlalchemy.org/en/latest/dialects/sqlite.html
    if config.get_sql_db_uri_params()[0] == 'sqlite':
        __table_args__ = {'sqlite_autoincrement': True}

    # Fields
    id = Column(
        Integer,
        autoincrement=True,
        nullable=False,
        primary_key=True,
        name='id'
    )
    sha256 = Column(
        String(length=64),
        index=True,
        name='sha256'
    )
    sha1 = Column(
        String(length=40),
        index=True,
        name='sha1'
    )
    md5 = Column(
        String(length=32),
        index=True,
        name='md5'
    )
    timestamp_first_scan = Column(
        String,
        nullable=False,
        name='timestamp_first_scan'
    )
    timestamp_last_scan = Column(
        String,
        nullable=False,
        name='timestamp_last_scan'
    )
    size = Column(
        Integer,
        name='size'
    )
    path = Column(
        String(length=255),
        name='path'
    )
    # Many to many Tag <-> File
    tags = relationship(
        'Tag',
        secondary=tag_file,
        backref='files'
    )

    def __init__(self, timestamp_first_scan, timestamp_last_scan, tags=[]):
        super(File, self).__init__()

        self.timestamp_first_scan = timestamp_first_scan
        self.timestamp_last_scan = timestamp_last_scan
        self.tags = tags

    @classmethod
    def load_from_sha256(cls, sha256, session):
        """Find the object in the database
        :param sha256: the sha256 to look for
        :param session: the session to use
        :rtype: cls
        :return: the object that corresponds to the sha256
        :raise: IrmaDatabaseResultNotFound, IrmaDatabaseError
        """
        try:
            return session.query(cls).filter(
                cls.sha256 == sha256
            ).one()
        except NoResultFound as e:
            raise IrmaDatabaseResultNotFound(e)
        except MultipleResultsFound as e:
            raise IrmaDatabaseError(e)

    @classmethod
    def load_from_sha1(cls, sha1, session):
        """Find the object in the database
        :param sha1: the sha1 to look for
        :param session: the session to use
        :rtype: cls
        :return: the object that corresponds to the sha1
        :raise: IrmaDatabaseResultNotFound, IrmaDatabaseError
        """
        try:
            return session.query(cls).filter(
                cls.sha1 == sha1
            ).one()
        except NoResultFound as e:
            raise IrmaDatabaseResultNotFound(e)
        except MultipleResultsFound as e:
            raise IrmaDatabaseError(e)

    @classmethod
    def load_from_md5(cls, md5, session):
        """Find the object in the database
        :param md5: the md5 to look for
        :param session: the session to use
        :rtype: cls
        :return: the object that corresponds to the md5
        :raise: IrmaDatabaseResultNotFound, IrmaDatabaseError
        """
        try:
            return session.query(cls).filter(
                cls.md5 == md5
            ).one()
        except NoResultFound as e:
            raise IrmaDatabaseResultNotFound(e)
        except MultipleResultsFound as e:
            raise IrmaDatabaseError(e)

    def save_file_to_fs(self, data):
        """Add a sample
        :param data: the sample file
        :raise: IrmaFileSystemError if there is a problem with the filesystem
        """
        # helper to split files in subdirs
        def build_path(sha256):
                PREFIX_NB = 3
                PREFIX_LEN = 2
                base_path = config.get_samples_storage_path()
                if (PREFIX_NB * PREFIX_LEN) > len(sha256):
                    raise IrmaValueError("too much prefix for file storage")
                path = base_path
                for i in xrange(0, PREFIX_NB + 1, PREFIX_LEN):
                    path = os.path.join(path, sha256[i:i + PREFIX_LEN])
                if not os.path.exists(path):
                    os.makedirs(path)
                if not os.path.isdir(path):
                    reason = "storage path is not a directory"
                    raise IrmaFileSystemError(reason)
                return os.path.join(path, sha256)

        sha256 = hashlib.sha256(data).hexdigest()
        # split files between subdirs
        path = build_path(sha256)
        try:
            with open(path, 'wb') as h:
                h.write(data)
        except IOError:
            raise IrmaFileSystemError(
                'Cannot add the sample {0} to the collection'.format(sha256)
            )

        self.sha256 = sha256
        self.sha1 = hashlib.sha1(data).hexdigest()
        self.md5 = hashlib.md5(data).hexdigest()
        self.size = len(data)
        self.path = path

    def remove_file_from_fs(self):
        """Remove the sample
        :raise: IrmaFileSystemError if there is a problem with the filesystem
        """
        try:
            if self.path is None:
                return
            os.remove(self.path)
            self.path = None
        except OSError as e:
            raise IrmaFileSystemError(e)

    @classmethod
    def remove_old_files(cls, max_age, session):
        """Remove the files that are older than timestamp() - max_age
        from the file system
        :param max_age: the files older than timestamp() - max_age
            will be deleted
        :rtype: int
        :return: the number of deleted files
        """
        fl = session.query(cls).filter(
            cls.timestamp_last_scan < compat.timestamp() - max_age
        ).all()
        for f in fl:
            f.remove_file_from_fs()

        return len(fl)

    def get_file_names(self):
        """Fetch the different names of the file
        :rtype: list
        :return: list of filenames
        """
        from_web = []
        for fw in self.files_web:
            from_web.append(fw.name)
        from_submission = []
        for fa in self.files_agent:
            from_submission.append(os.path.split(fa.submission_path)[1])
        return list(set(from_web + from_submission))


class ProbeResult(Base, SQLDatabaseObject):
    __tablename__ = '{0}probeResult'.format(tables_prefix)

    # SQLite fix for auto increment on ids
    # see http://docs.sqlalchemy.org/en/latest/dialects/sqlite.html
    if config.get_sql_db_uri_params()[0] == 'sqlite':
        __table_args__ = {'sqlite_autoincrement': True}

    # Fields
    id = Column(
        Integer,
        autoincrement=True,
        nullable=False,
        primary_key=True,
        name='id'
    )
    probe_type = Column(
        String,
        name='probe_type'
    )
    probe_name = Column(
        String,
        nullable=False,
        name='probe_name'
    )
    nosql_id = Column(
        String,
        name='nosql_id'
    )
    result = Column(
        Integer,
        name='result'
    )
    # Many to many ProbeResult <-> FileWeb
    files_web = relationship(
        'FileWeb',
        secondary=probe_result_file_web,
        backref='probe_results'
    )
    # Many to many ProbeResult <-> File
    id_file = Column(
        Integer,
        ForeignKey('{0}file.id'.format(tables_prefix))
    )
    file = relationship(
        "File",
        backref=backref('ref_results')
    )

    def __init__(self,
                 probe_type,
                 probe_name,
                 nosql_id,
                 result,
                 file_web=None):
        super(ProbeResult, self).__init__()

        self.probe_type = probe_type
        self.probe_name = probe_name
        self.nosql_id = nosql_id
        self.result = result
        self.files_web = [file_web]


class Scan(Base, SQLDatabaseObject):
    __tablename__ = '{0}scan'.format(tables_prefix)

    # SQLite fix for auto increment on ids
    # see http://docs.sqlalchemy.org/en/latest/dialects/sqlite.html
    if config.get_sql_db_uri_params()[0] == 'sqlite':
        __table_args__ = {'sqlite_autoincrement': True}

    # Fields
    id = Column(
        Integer,
        autoincrement=True,
        nullable=False,
        primary_key=True,
        name='id'
    )
    external_id = Column(
        String(length=36),
        index=True,
        nullable=False,
        name='external_id'
    )
    date = Column(
        Integer,
        nullable=False,
        name='date'
    )
    ip = Column(
        String,
        name='ip'
    )

    def __init__(self, date, ip):
        super(Scan, self).__init__()
        self.external_id = UUID.generate()
        self.date = date
        self.ip = ip

    @classmethod
    def load_from_ext_id(cls, external_id, session):
        """Find the object in the database
        :param external_id: the id to look for
        :param session: the session to use
        :rtype: cls
        :return: the object that corresponds to the external_id
        :raise: IrmaDatabaseResultNotFound, IrmaDatabaseError
        """
        try:
            return session.query(cls).filter(
                cls.external_id == external_id
            ).one()
        except NoResultFound as e:
            raise IrmaDatabaseResultNotFound(e)
        except MultipleResultsFound as e:
            raise IrmaDatabaseError(e)

    def finished(self):
        """Tell if the scan is over or not
        :rtype: boolean
        :return: True if the scan is over
        """
        if self.status == IrmaScanStatus.finished:
            return True
        if self.status < IrmaScanStatus.launched:
            return False
        for fw in self.files_web:
            for pr in fw.probe_results:
                if pr.nosql_id is None:
                    return False
        return True

    @property
    def status(self):
        return max(evt.status for evt in self.events)

    def set_status(self, status_code, session):
        if status_code not in IrmaScanStatus.label.keys():
            raise IrmaCoreError("Trying to update with an unknown status")
        if status_code not in [evt.status for evt in self.events]:
            evt = ScanEvents(status_code, self)
            evt.save(session)


class FileWeb(Base, SQLDatabaseObject):
    __tablename__ = '{0}fileWeb'.format(tables_prefix)

    # SQLite fix for auto increment on ids
    # see http://docs.sqlalchemy.org/en/latest/dialects/sqlite.html
    if config.get_sql_db_uri_params()[0] == 'sqlite':
        __table_args__ = {'sqlite_autoincrement': True}

    # Fields
    id = Column(
        Integer,
        autoincrement=True,
        nullable=False,
        primary_key=True,
        name='id'
    )
    # Many to one FileWeb <-> File as part of the primary key
    id_file = Column(
        Integer,
        ForeignKey('{0}file.id'.format(tables_prefix)),
        nullable=False,
        # conceptually it should be a PFK, but due to limitation in sqlite,
        # only is a FK
        # https://groups.google.com/forum/#!topic/sqlalchemy/TxISzgW7xUg
        # primary_key=True
    )
    file = relationship(
        "File",
        backref=backref('files_web')
    )
    name = Column(
        String(length=255),
        nullable=False,
        name='name'
    )
    # Many to one FileWeb <-> Scan
    id_scan = Column(
        Integer,
        ForeignKey('{0}scan.id'.format(tables_prefix)),
        nullable=False
    )
    scan = relationship(
        "Scan",
        backref=backref('files_web')
    )

    def __init__(self, file, name, scan):
        super(FileWeb, self).__init__()

        self.file = file
        self.name = name
        self.scan = scan

    @classmethod
    def find_by_name(cls, name, strict, session):
        """Find the object in the database
        :param name: the name to look for
        :param strict: boolean to check with partial name or strict name
        :param session: the session to use
        :rtype: cls
        :return: the object thats corresponds to the partial name
        :raise: IrmaDatabaseResultNotFound, IrmaDatabaseError
        """
        try:
            if strict:
                return session.query(cls).filter(
                    cls.name == name
                    ).all()
            else:
                return session.query(cls).filter(
                    cls.name.like("%{0}%".format(name))
                    ).all()
        except NoResultFound as e:
            raise IrmaDatabaseResultNotFound(e)


class FileAgent(Base, SQLDatabaseObject):
    __tablename__ = '{0}fileAgent'.format(tables_prefix)

    # SQLite fix for auto increment on ids
    # see http://docs.sqlalchemy.org/en/latest/dialects/sqlite.html
    if config.get_sql_db_uri_params()[0] == 'sqlite':
        __table_args__ = {'sqlite_autoincrement': True}

    # Fields
    id = Column(
        Integer,
        autoincrement=True,
        nullable=False,
        primary_key=True,
        name='id'
    )
    submission_path = Column(
        String(length=255),
        nullable=False,
        name='submission_path'
    )
    # Many to one FileAgent <-> File as part of the primary key
    id_file = Column(
        Integer,
        ForeignKey('{0}file.id'.format(tables_prefix)),
        nullable=False,
        # conceptually it should be a PFK, but due to limitation in sqlite,
        # only is a FK
        # https://groups.google.com/forum/#!topic/sqlalchemy/TxISzgW7xUg
        # primary_key=True
    )
    file = relationship(
        "File",
        backref=backref('files_agent')
    )
    # Many to one FileAgent <-> Submission
    id_s = Column(
        Integer,
        ForeignKey('{0}submission.id'.format(tables_prefix)),
        nullable=False
    )
    submission = relationship(
        "Submission",
        backref=backref('files_agent')
    )

    def __init__(self, file, submission_path, submission):
        super(FileAgent, self).__init__()

        self.file = file
        self.submission_path = submission_path
        self.submission = submission


class Submission(Base, SQLDatabaseObject):
    __tablename__ = '{0}submission'.format(tables_prefix)

    # SQLite fix for auto increment on ids
    # see http://docs.sqlalchemy.org/en/latest/dialects/sqlite.html
    if config.get_sql_db_uri_params()[0] == 'sqlite':
        __table_args__ = {'sqlite_autoincrement': True}

    # Fields
    id = Column(
        Integer,
        autoincrement=True,
        nullable=False,
        primary_key=True,
        name='id'
    )
    external_id = Column(
        String(length=36),
        index=True,
        nullable=False,
        name='external_id'
    )
    os_name = Column(
        String,
        nullable=False,
        name='os_name'
    )
    username = Column(
        String,
        nullable=False,
        name='username'
    )
    ip = Column(
        String,
        nullable=False,
        name='ip'
    )
    date = Column(
        Integer,
        nullable=False,
        name='date'
    )

    def __init__(self, os_name, username, ip, date):
        super(Submission, self).__init__()

        self.external_id = UUID.generate()
        self.os_name = os_name
        self.username = username
        self.ip = ip
        self.date = date

    @classmethod
    def load_from_ext_id(cls, external_id, session):
        """Find the object in the database
        :param external_id: the id to look for
        :param session: the session to use
        :rtype: cls
        :return: the object that corresponds to the external_id
        :raise IrmaDatabaseResultNotFound, IrmaDatabaseError
        """
        try:
            return session.query(cls).filter(
                cls.external_id == external_id
            ).one()
        except NoResultFound as e:
            raise IrmaDatabaseResultNotFound(e)
        except MultipleResultsFound as e:
            raise IrmaDatabaseError(e)


class ScanEvents(Base, SQLDatabaseObject):
    __tablename__ = '{0}scanEvents'.format(tables_prefix)

    # SQLite fix for auto increment on ids
    # see http://docs.sqlalchemy.org/en/latest/dialects/sqlite.html
    if config.get_sql_db_uri_params()[0] == 'sqlite':
        __table_args__ = {'sqlite_autoincrement': True}

    # Fields
    id = Column(
        Integer,
        autoincrement=True,
        nullable=False,
        primary_key=True,
        name='id'
    )
    status = Column(
        Integer,
        nullable=False,
        name='status'
    )
    timestamp = Column(
        String,
        nullable=False,
        name='timestamp'
    )
    # Many to one FileWeb <-> Scan
    id_scan = Column(
        Integer,
        ForeignKey('{0}scan.id'.format(tables_prefix)),
        nullable=False
    )
    scan = relationship(
        "Scan",
        backref=backref('events')
    )

    def __init__(self, status, scan):
        super(ScanEvents, self).__init__()
        self.status = status
        self.timestamp = compat.timestamp()
        self.scan = scan


Base.metadata.create_all(SQLDatabase.get_engine())