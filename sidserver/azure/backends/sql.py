# Copyright 2012 OpenStack LLC
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

from sidserver.common import sql
from sidserver import exception


class AzureSIPModel(sql.ModelBase, sql.DictBase):
    __tablename__ = 'AzureSIPs'
    attributes = ['sip_account_id', 'account_name', 'sip_members', 'status']
    sip_account_id = sql.Column(sql.String(64), primary_key=True)
    account_name = sql.Column(sql.String(64), nullable=True)
    sip_members = sql.Column(sql.JsonBlob(), nullable=True)
    status = sql.Column(sql.String(1), nullable=True)
    sid_id = sql.Column(sql.String(32), nullable=True)
    
class AzureSIDModel(sql.ModelBase, sql.DictBase):
    __tablename__ = 'AzureSIDs'
    attributes = ['sid_id', 'sid_name', 'sid_members', 'status']
    sid_id = sql.Column(sql.String(32), primary_key=True)
    sid_name = sql.Column(sql.String(32), nullable=True)
    sid_members = sql.Column(sql.JsonBlob(), nullable=True)
    status = sql.Column(sql.String(1), nullable=True)
    

class AzureSIPs():

    @sql.handle_conflicts(conflict_type='sip')
    def add_sip(self, sip):
        session = sql.get_session()
        with session.begin():
            ref = AzureSIPModel.from_dict(sip)
            session.add(ref)

        return ref.to_dict()

    def list_sips(self):
        session = sql.get_session()
        refs = session.query(AzureSIPModel).all()
	#refs = query.filter_by(status="0").all()
        return [ref.to_dict() for ref in refs]

    def list_available_sips(self):
        session = sql.get_session()
        #refs = session.query(AzureSIPModel).all()
	refs = session.query(AzureSIPModel).filter_by(status="0").all()
        return [ref.to_dict() for ref in refs]

    def get_sip(self, sip_account_id):
        session = sql.get_session()
        ref = session.query(AzureSIPModel).get(sip_account_id)
        if not ref:
            raise exception.NotFound(target=sip_account_id)
        return ref.to_dict()

    @sql.handle_conflicts(conflict_type='sip')
    def update_sip(self, sip_account_id, sip):
        session = sql.get_session()
        with session.begin():
            ref = self._get_sip(session, sip_account_id)
	    old_dict = ref.to_dict()
	    for k in sip:
		old_dict[k] = sip[k]
	    new_sip = AzureSIPModel.from_dict(old_dict)
	    ref.account_name = new_sip.account_name
	    ref.sip_members = new_sip.sip_members
	    ref.status = new_sip.status
        return ref.to_dict()

    def delete_sip(self, sip_account_id):
        session = sql.get_session()
        with session.begin():
            ref = self._get_sip(session, sip_account_id)
            session.delete(ref)
	return

    def _get_sip(self, session, sip_account_id):
        """Private method to get a sip model object (NOT a dictionary)."""
        ref = session.query(AzureSIPModel).get(sip_account_id)
        if not ref:
            raise exception.NotFound(target=sip_account_id)
        return ref


class AzureSIDs():

    @sql.handle_conflicts(conflict_type='sid')
    def add_sid(self, sid):
        session = sql.get_session()
        with session.begin():
            ref = AzureSIDModel.from_dict(sid)
            session.add(ref)
        return ref.to_dict()

    def list_sids(self):
        session = sql.get_session()
        refs = session.query(AzureSIDModel).all()
        return [ref.to_dict() for ref in refs]

    def get_sid(self, sid_id):
        session = sql.get_session()
        ref = session.query(AzureSIDModel).get(sid_id)
        if not ref:
            raise exception.NotFound(target=sid_id)
        return ref.to_dict()

    def delete_sid(self, sid_id):
        session = sql.get_session()
        with session.begin():
            ref = self._get_sid(session, sid_id)
            session.delete(ref)
	return

    def _get_sid(self, session, sid_id):
        """Private method to get a sid model object (NOT a dictionary)."""
        ref = session.query(AzureSIDModel).get(sid_id)
        if not ref:
            raise exception.NotFound(target=sid_id)
        return ref

