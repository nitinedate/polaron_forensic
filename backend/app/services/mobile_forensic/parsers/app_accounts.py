"""Acquired Android package, user and account records with source pointers."""
from __future__ import annotations

import re
from pathlib import PurePosixPath
from xml.etree import ElementTree as ET

from app.services.mobile_forensic.models import NormalizedArtifact
from app.services.mobile_forensic.plugins import ArtifactParser


class AppAccountsParser(ArtifactParser):
    name='app_accounts_parser';version='1.0.0';domains=('device_os','accounts_contacts')
    _NAMES={'packages.xml','packages.list','packages_all.txt','packages_installed.txt','packages_disabled.txt',
            'users.txt','accounts.txt','accounts.db','accounts_ce.db','accounts_de.db'}

    def supports(self,item,context):
        return PurePosixPath(item.path.replace('\\','/').lower()).name in self._NAMES

    def parse(self,item,context):
        name=PurePosixPath(item.path.replace('\\','/').lower()).name
        limit=768_000_000 if name.endswith('.db') else 256*1024*1024
        blob=context.read_artifact_bytes(item.path,max_bytes=limit)
        if blob is None or item.size and len(blob)<item.size:
            raise ValueError('Account/application source unavailable or partially read')
        if name.endswith('.db'):
            from app.services.mobile_forensic.parsers._sqlite_util import open_sqlite_bytes,table_names,iter_query,column_name_map
            if not blob.startswith(b'SQLite format 3\x00'):
                raise ValueError('Accounts database needs its matching decryption/readable export before parsing')
            with open_sqlite_bytes(blob) as conn:
                if conn is None:raise ValueError('Unreadable accounts SQLite')
                if 'accounts' not in table_names(conn):return
                columns=column_name_map(conn,'accounts')
                if not {'name','type'}<=set(columns):raise ValueError('Unknown accounts schema')
                # Identity records only; acquired credential/token bytes stay in
                # their source rather than being copied into report prose.
                selected=[columns[key] for key in ('_id','name','type','previous_name','last_password_entry_time_millis_epoch') if key in columns]
                query='SELECT '+','.join('"'+col.replace('"','""')+'"' for col in selected)+' FROM accounts'
                for index,row in enumerate(iter_query(conn,query)):
                    yield self._record(item,context,'device_account',{'artifact_family':'accounts','name':row.get('name'),
                        'account_type':row.get('type'),'fields':row,'reference_only':True},str(row.get('_id',index)),table='accounts')
            return
        text=blob.decode('utf-8-sig')
        if name=='packages.xml':
            if re.search(r'<!\s*(?:DOCTYPE|ENTITY)',text,re.I):raise ValueError('DOCTYPE is not supported in package registry XML')
            for index,node in enumerate(ET.fromstring(text).iter('package')):
                if node.get('name'):
                    yield self._record(item,context,'application_record',{'artifact_family':'applications','package':node.get('name'),
                        'fields':dict(node.attrib),'reference_only':True,'note':'Package registry entry; installation/use must be correlated with acquired files and activity.'},f'package/{index}')
            return
        for line_number,line in enumerate(text.splitlines(),1):
            if name.startswith('packages_'):
                match=re.match(r'^package:(.+)$',line.strip())
                if not match:continue
                value=match[1];path,separator,package=value.rpartition('=')
                package=package if separator else value
                current=name in {'packages_installed.txt','packages_disabled.txt'}
                yield self._record(item,context,'installed_app' if current else 'application_record',
                    {'artifact_family':'applications','package':package,'apk_path':path if separator else None,
                     'disabled':name=='packages_disabled.txt','reference_only':True,
                     'note':'Acquired package-manager listing; includes retained/uninstalled entries.' if not current else 'Acquired installed-package listing; does not establish execution or misuse.'},f'line/{line_number}')
            elif name=='packages.list':
                fields=line.split()
                if len(fields)>=2 and fields[1].isdigit():
                    yield self._record(item,context,'application_record',{'artifact_family':'applications','package':fields[0],
                        'uid':fields[1],'fields':fields,'reference_only':True},f'line/{line_number}')
            elif name=='users.txt':
                match=re.search(r'UserInfo\{(\d+):([^:}]+):([^}]+)\}',line)
                if match:
                    yield self._record(item,context,'device_user',{'artifact_family':'accounts','user_id':match[1],
                        'name':match[2],'flags':match[3],'raw_line':line},f'line/{line_number}')
            elif name=='accounts.txt':
                match=re.search(r'Account\s*\{name=(.*?),\s*type=([^}]+)\}',line)
                if match:
                    yield self._record(item,context,'device_account',{'artifact_family':'accounts','name':match[1],
                        'account_type':match[2],'raw_line':line,'reference_only':True},f'line/{line_number}')

    def _record(self,item,context,kind,data,pointer,table=None):
        return NormalizedArtifact.create(artifact_type=kind,source_domain='accounts_contacts' if kind in {'device_account','device_user'} else 'device_os',
            data=data,state='allocated',source_path=item.path,source_table=table,source_row_id=pointer,source_sha256=item.sha256,
            parser=self.name,parser_version=self.version,job_id=context.job_id,source_id=context.source_id)
