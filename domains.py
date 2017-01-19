#!/usr/bin/python2
# -*- coding: utf-8 -*-

from peewee import *
import socket, struct

settings = {
    'database': '/opt/dnsfw/domains.db',
    'redirect_addr': '127.0.0.1'
}

def addr_ddn_to_int(addr):
    return struct.unpack("!I", socket.inet_aton(addr))[0]

def addr_int_to_ddn(addr_int):
    return socket.inet_ntoa(struct.pack("!I", addr_int))

def domain_valid(domain):
    # domain should not be numeric string
    try:
        int(domain)
        return False
    except:
        # domain should resolve
        try:
            socket.getaddrbyname(domain)
        except:
            return False
    return True

database = SqliteDatabase(settings['database'])

class BaseModel(Model):
    class Meta:
        database = database

class Domain(BaseModel):
    name = CharField(unique=True)

class ScrapedTag(BaseModel):
    source = CharField()
    name = CharField()
    bwld_name = CharField()
    class Meta:
        indexes = (
            (('source', 'tag'), True),
        )

class DomainScrapedTag(BaseModel):
    domain = ForeignKeyField(Domain)
    tag = ForeignKeyField(ScrapedTag)
    class Meta:
        indexes = (
            (('domain', 'tag'), True),
        )

class Tag(BaseModel):
    name = CharField(unique=True)
    # for anonymous user and initial client settings
    forbidden_default = BooleanField(default=False)

class Client(BaseModel):
    username = CharField(unique=True)
    password = CharField()
    is_admin = BooleanField(default=False)
    # whether to block or not domains which have both forbidden and permitted tags
    allow_mixed = BooleanField(default=False)
    # whether to block or not domains which have no tags
    allow_untagged = BooleanField(default=True)

class DomainTag(BaseModel):
    domain = ForeignKeyField(Domain)
    tag = ForeignKeyField(Tag)
    class Meta:
        indexes = (
            (('domain', 'tag'), True),
        )
    # whether domain tag is accepted (active), rejected or waiting (on vote) 
    state = BooleanField(null=True, default=None)
    # client who submitted domain tag
    # TODO: add vote (for/against) field and change unique restriction to (domain, tag, client)
    # state will be decided from admin vote
    client = ForeignKeyField(Client, null=True)

# we store forbidden tag references and consider unreferenced tags as accepted by client
# we don't use defaults for existing user, because this would make it uncertain for client whether he has set tag manually, or it has default state which can be changed by admin later
# we assume per-client state for new tags from Client.allow_mixed switch: if it's on, new tags are off (no ClientForbiddenTag reference to new tag created automatically for such users); if it's off, new tags are on (ClientForbiddenTag reference to new created automatically for such users)
# this way, client shouldn't encounter unexpected behaivour changes for websites he had blocked or made accessible
class ClientForbiddenTag(BaseModel):
    client = ForeignKeyField(Client)
    tag = ForeignKeyField(Tag)
    class Meta:
        indexes = (
            (('client', 'tag'), True),
        )

class ClientNet(BaseModel):
    client = ForeignKeyField(Client)
    name = CharField()
    # store IP as int, provide method to get dot-decimal notation
    addr = IntegerField()
    def addr_ddn(self):
        return socket.inet_ntoa(struct.pack("!I", self.addr))

# filter only needs tags to check if domain is blocked
# webapp needs both tags and domain, which can be not request domain but an upper-level domain which they are inherited from

# if domain has no active tags, active tags of first parent domain which has ones apply
def get_tagged_domain(domain):
    # get domains list, e. g. 'img.girls.xxx' -> ['img.girls.xxx', 'girls.xxx', 'xxx']
    domains = [domain]
    while '.' in domains[-1]:
        domains.append(domains[-1].split('.', 1)[1])
    # get domain tags of the first domain in the list which has tags, if there is one
    for sliced_domain in domains:
        if Tag.select(Tag.name).where(Tag.id<<DomainTag.select(DomainTag.tag).where(DomainTag.domain<<Domain.select(Domain.id).where(Domain.name==sliced_domain))).exists():
            return sliced_domain
    return None

def get_domain_tag_names(domain):
    tagged_domain = get_tagged_domain(domain)
    if tagged_domain:
        return [tag.name for tag in Tag.select(Tag.name).where(Tag.id<<DomainTag.select(DomainTag.tag).where(DomainTag.domain<<Domain.select(Domain.id).where(Domain.name==tagged_domain)))]
    return []

# filter only needs boolean which indicates whether domain is blocked
# webapp needs reason with list of forbidden tags

def domain_allowed_for_client(domain, client=None):
    # client with id=1 is used to set settings for anonymous users
    # if there is no such client in db, simply allow everything (alternative: block everything and show "unconfigured!" message on block page?)
    if client is None:
        if Client.select().where(Client.id==1).exists():
            client = Client.get(id=1)
        else:
            return True
    forbidden_tags = [tag.name for tag in Tag.select().where(Tag.id<<ClientForbiddenTag.select(ClientForbiddenTag.tag).where(ClientForbiddenTag.client==client.id))]
    domain_tags = get_domain_tag_names(domain)
    # untagged
    if not domain_tags:
    	# reason: website is not categorized
    	return client.allow_untagged
    # compare and take decision
    if not client.allow_mixed:
    	# reason: website in forbidden categories [tag for tag in domain_tags if tag in forbidden_tags]
        return not any([tag in forbidden_tags for tag in domain_tags])
    else:
        # reason: website is not in any allowed category
        return any([tag not in forbidden_tags for tag in domain_tags])

def domain_allowed_for_addr(domain, addr):
    addr_int = addr_ddn_to_int(addr)
    # in case of collision of multiple clients sharing one ip, domain will be blocked if it's blocked by any of clients' settings
    # this prevents user to register and hijack ip for his account with permissive settings
    if Client.select().where(Client.id<<ClientNet.select(ClientNet.client).where(ClientNet.addr==addr_int)).exists():
        for client in Client.select().where(Client.id<<ClientNet.select(ClientNet.client).where(ClientNet.addr==addr_int)):
            if not domain_allowed_for_client(domain, client): return False
        return True
    return domain_allowed_for_client(domain)
