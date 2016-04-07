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


class SIPModel(sql.ModelBase, sql.DictBase):
    __tablename__ = 'sip_accounts'
    attributes = ['id', 'account_info', 'status']
    id = sql.Column(sql.String(64), primary_key=True)
    account_info = sql.Column(sql.String(), nullable=False)
    status = sql.Column(sql.String(64), nullable=False)
    


class SIPs():

    @sql.handle_conflicts(conflict_type='sip')
    def add_sip(self, sip):
        session = sql.get_session()

        with session.begin():
            ref = SIPModel.from_dict(sip)
            session.add(ref)

        return ref.to_dict()

    def list_sips(self):
        session = sql.get_session()
        query = session.query(SIPModel)
	refs = query.filter_by(status="Available").all()
        return [ref.to_dict() for ref in refs]

    def _get_sip(self, session, sip_id):
        """Private method to get a sip model object (NOT a dictionary)."""
        ref = session.query(SipInfo).get(sip_id)
        if not ref:
            raise exception.NotFound(target=sip)
        return ref

    @sql.handle_conflicts(conflict_type='sip')
    def update_sip(self, sip, status):
        session = sql.get_session()

        with session.begin():
            ref = self._get_sip(session, sip)
            ref.status = status

        return ref.to_dict()

    def delete_sip(self, sip_id):
        session = sql.get_session()

        with session.begin():
            ref = self._get_sip(session, sip_id)
            session.delete(ref)

