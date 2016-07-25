# Copyright (c) 2013-2016 Quarkslab.
# Copyright (c) 2016 Teclib.
#
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

import logging
import zipfile
import StringIO
from bottle import response, request

from frontend.api.v1_1.errors import process_error
from frontend.helpers.utils import guess_hash_type
from frontend.models.sqlobjects import FileWeb, File
from frontend.api.v1_1.schemas import FileWebSchema_v1_1, ScanSchema_v1_1, \
    FileSchema_v1_1
from lib.common.utils import decode_utf8
from lib.irma.common.exceptions import IrmaDatabaseResultNotFound


file_web_schema = FileWebSchema_v1_1()
scan_schema = ScanSchema_v1_1()
file_web_schema.context = {'formatted': True}
log = logging.getLogger(__name__)


def get_archive(db):
    """ Search a file using query filters (tags + hash or name). Support
        pagination.
    :param all params are sent using query method
    :rtype: dict of 'total': int, 'page': int, 'per_page': int,
        'items': list of file(s) found
    :return:
        on success 'items' contains a list of files found
        on error 'msg' gives reason message
    """
    try:
        name = None
        if 'name' in request.query:
            name = decode_utf8(request.query['name'])

        h_value = request.query.hash or None

        search_tags = request.query.tags or None
        if search_tags is not None:
            search_tags = search_tags.split(',')

        log.debug("name %s h_value %s search_tags %s",
                  name, h_value, search_tags)
        if name is not None and h_value is not None:
            raise ValueError("Can't find using both name and hash")

        # Options query
        offset = int(request.query.offset) if request.query.offset else 0
        limit = int(request.query.limit) if request.query.limit else 25

        if name is not None:
            base_query = FileWeb.query_find_by_name(name, search_tags, db)
        elif h_value is not None:
            h_type = guess_hash_type(h_value)

            if h_type is None:
                raise ValueError("Hash not supported")

            base_query = FileWeb.query_find_by_hash(
                h_type, h_value, search_tags, db)
        else:
            # FIXME this is just a temporary way to output
            # all files, need a dedicated
            # file route and controller
            base_query = FileWeb.query_find_by_name("", search_tags, db)

        # TODO: Find a way to move pagination as a BaseQuery like in
        #       flask_sqlalchemy.
        # https://github.com/mitsuhiko/flask-sqlalchemy/blob/master/flask_sqlalchemy/__init__.py#L422
        items = base_query.limit(limit).offset(offset).all()

        sha256_list = []

        for i, val in enumerate(items):            
            #log.debug("Debug :: items[%s] = %s ::",i, val.file.sha256)
            fhash = val.file.sha256
            sha256_list.append(fhash)
            #file_web.file.sha256
        
        if sha256_list is not None:
            return _download_zip(sha256_list,db)
        
    except Exception as e:
        log.exception(e)
        process_error(e)




# called by get_archive
def _download_zip(hash_list, db):
    
    s = StringIO.StringIO()

    # Create zip archive
    zf = zipfile.ZipFile(s,'w')

    for i, val in enumerate(hash_list):

        # Retrieve a file based on its sha256"""
        fobj = File.load_from_sha256(val, db)
        #log.debug("Debug :: download_zip :: items[%s] = %s ::",i, fobj)
        if fobj.path is None:
            raise IrmaDatabaseResultNotFound("downloading a removed file")
        # Add file to archive
        zf.write(fobj.path,fobj.sha256)


    ctype = 'application/zip'
    # Suggest Filename to "irma_archive"
    # Todo: generate archive name dynamically.
    cdisposition = "attachment; filename={}".format('irma_archive.zip')
    response.headers["Content-Type"] = ctype
    response.headers["Content-Disposition"] = cdisposition
    
    zf.close()

    return s.getvalue()
