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


def get_stats(db):
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
        limit = int(request.query.limit) if request.query.limit else 0

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
        #items = base_query.limit(limit).offset(offset).all()
        items = base_query.all()


        files_infos = file_web_schema.dump(items, many=True).data



        # Process items found statistiques.
        #log.debug("Debug ::::::::::::: items : %s", type(items))
        #log.debug("Debug ::::::::::::: files_infos: %s", type(files_infos))

        
        stats = []

        stats_fake = [
                    {'name': 'armaditoAV', 'version':3.14, 'nbsamples':2,  'malware': 1, 'clean':1, 'errors':0},
                    {'name': 'clamav', 'version':3.14, 'nbsamples':2, 'malware': 1, 'clean':1, 'errors':0},
        ]


        for i, val in enumerate(files_infos):
            
            #dsds
            log.debug("Debug :::::::::::::: results : %s :: %s", type(val['probe_results']), val['probe_results'])

            #log.debug("Debug :::::::::::::: results : %s", type(val.probe_results))
            probe_results = val['probe_results']
            

            for j, res in enumerate(probe_results):

                #log.debug("Debug :::::::::::::: probe_result : %s", type(res))
                # Get av name
                #log.debug("Debug :::::::::::::: av_name : %s", res.name)
                #log.debug("Debug :::::::::::::: av_type : %s", res.type)
                #log.debug("Debug :::::::::::::: av_version : %s", res.version)

                if res.type == "antivirus":
                    add_stats(stats,res)


        if offset == 0 and len(items) < limit:
            total = len(items)
        else:
            total = base_query.count()

        log.debug("Found %s results", total)
        response.content_type = "application/json; charset=UTF-8"
        return {
            'total': total,
            'offset': offset,
            'limit': limit,
            'items': stats,
        }
    except Exception as e:
        log.exception(e)
        process_error(e)



def add_stats(stats, result):

    
    for i, val in enumerate(stats):

        #log.debug("Debug :: add_stats :: val = %s :: %s", type(val), val['name'])
        if val['name'] == result.name:
            # update stats.
            val['total'] += 1
            val['infected'] = val['infected']+1 if result.status == 1 else val['infected']
            val['clean'] = val['clean']+1 if result.status == 0 else val['clean']
            val['errors'] = val['errors']+1 if result.status == -1 else val['errors']
            return 1


    # add new entry in av stats:
    av = {  "name":result.name,
            "version": result.version,
            "total": 1,
            "infected": 1 if result.status == 1 else 0 ,
            "clean": 1 if result.status == 0 else 0 ,
            "errors": 1 if result.status == -1 else 0
    }
    stats.append(av)
    
    
    return 0
