from datetime import datetime, timezone


class Message(object):
    @staticmethod
    def get_content_type():
        return 'multipart/alternative'


MAIL_STRING = """Delivered-To: to@test1.com
MIME-Version: 1.0
From: John Smith <from@test1.com>
Date: Mon, 10 Aug 2020 10:17:16 +0300
Subject: Testing email for mail listener
To: to@test1.com
Content-Type: multipart/alternative; boundary="0000000000002b271405ac80bf8b"


--0000000000002b271405ac80bf8b
Content-Type: text/plain; charset="UTF-8"



--0000000000002b271405ac80bf8b
Content-Type: text/html; charset="UTF-8"

<div dir="ltr"><br></div>

--0000000000002b271405ac80bf8b--
"""

EXPECTED_LABELS = [
    {'type': 'Email/from', 'value': 'from@test1.com'},
    {'type': 'Email/format', 'value': 'multipart/alternative'}, {'type': 'Email/text', 'value': ''},
    {'type': 'Email/subject', 'value': 'Testing email for mail listener'},
    {'type': 'Email/headers/Delivered-To', 'value': 'to@test1.com'},
    {'type': 'Email/headers/MIME-Version', 'value': '1.0'},
    {'type': 'Email/headers/From', 'value': 'John Smith <from@test1.com>'},
    {'type': 'Email/headers/Date', 'value': 'Mon, 10 Aug 2020 10:17:16 +0300'},
    {'type': 'Email/headers/Subject', 'value': 'Testing email for mail listener'},
    {'type': 'Email/headers/To', 'value': 'to@test1.com'},
    {'type': 'Email/headers/Content-Type',
     'value': 'multipart/alternative; boundary="0000000000002b271405ac80bf8b"'},
    {'type': 'Email', 'value': 'to@test1.com'},
    {'type': 'Email/html', 'value': '<div dir="ltr"><br></div>'}]


def test_convert_to_incident():
    from MailListenerV2 import Email
    email = Email(MAIL_STRING.encode(), False, False, 0)
    incident = email.convert_to_incident()
    assert incident['attachment'] == []
    assert incident['occurred'] == email.date.isoformat()
    assert incident['details'] == email.text or email.html
    assert incident['name'] == email.subject


def test_generate_search_query():
    from MailListenerV2 import generate_search_query
    now = datetime.now(timezone.utc)
    permitted_from_addresses = ['test1@mail.com', 'test2@mail.com']
    permitted_from_domains = ['test1.com', 'domain2.com']
    assert generate_search_query(now, permitted_from_addresses, permitted_from_domains) == ['OR',
                                                                                            'OR',
                                                                                            'OR',
                                                                                            'FROM',
                                                                                            'test1@mail.com',
                                                                                            'FROM',
                                                                                            'test2@mail.com',
                                                                                            'FROM',
                                                                                            'test1.com',
                                                                                            'FROM',
                                                                                            'domain2.com',
                                                                                            'SINCE',
                                                                                            now]


def test_generate_labels():
    from MailListenerV2 import Email
    email = Email(MAIL_STRING.encode(), False, False, 0)
    labels = email._generate_labels()
    for label in EXPECTED_LABELS:
        assert label in labels
