import flask
import flask_login
from werkzeug.security import generate_password_hash, check_password_hash
import domains

login_manager = flask_login.LoginManager()
# risk of collisions between flask_login and peewee parent class members
class Client(domains.Client, flask_login.UserMixin):
    pass

app = flask.Flask(__name__)
login_manager.init_app(app)
app.secret_key = '12345'

@login_manager.user_loader
def load_user(user_id):
    return Client.get(id=user_id)

def check_auth(username, password):
    if Client.select().where(Client.username==username).exists():
        user = Client.get(username=username)
        if check_password_hash(user.password, password):
            return user
    return None

@app.route('/', methods=['GET'])
# check host, if foreign - show block page
def default():
    host = flask.request.host.split(':')[0]
    if host in ['localhost', '127.0.0.1']:
        return flask.redirect('/login', code='302')
    return flask.render_template('block.htm', domain=host)

# show domain tags
# submit tags for domain
# vote for/against tag: same as submit tag, extra var against    
@app.route('/domain/', defaults={'domain': None})
@app.route('/domain/<domain>', methods=['GET', 'POST'])
def domain(domain):
    if flask.request.method == 'POST':
        # check if domain is valid
        if flask_login.current_user.is_authenticated and (domains.Domain.select().where(domains.Domain.name==domain).exists() or domains.domain_valid(domain)):
            # should we use readable values for state, proposed/rejected/approved?
            # in any case, we can't use string request values '0' and '1' in db requests
            # should we select domain tag by id or by tag.id?
            # by tag.id, of course, to allow adding new tags
            # should we have possibility to remove domain tag, not just set it rejected?
            # if [privileged] user who added the tag sets it rejected, the tag is removed? no
            state = None if 'state' not in flask.request.form else int(flask.request.form['state'])
            if flask_login.current_user.is_admin:
                # if admin rejects tags which is already rejected, tag is removed
                if state == False and domains.Domain.select().where(domains.Domain.name==domain).exists() and domains.DomainTag.select().where(domains.DomainTag.domain==domains.Domain.get(name=domain).id, domains.DomainTag.tag==int(flask.request.form['tag']), domains.DomainTag.state==False).exists():
                    domains.DomainTag.delete().where(domains.DomainTag.domain==domains.Domain.get(name=domain).id, domains.DomainTag.tag==int(flask.request.form['tag'])).execute()
                # otherwise, tag is created/updated with requested state
                else:
                    domain_tag = domains.DomainTag.get_or_create(domain=domains.Domain.get_or_create(name=domain)[0].id, tag=int(flask.request.form['tag']), defaults={'state': state})[0]
                    if domain_tag.state != state:
                        domain_tag.state = state
                        domain_tag.save()
            # non privileged user can only propose tags
            elif state is None and not domains.DomainTag.select().where(domains.DomainTag.domain==domain&domains.DomainTag.tag==flask.request.form['tag']).exists():
                domains.DomainTag.create(domain=domains.Domain.get_or_create(name=domain)[0].id, tag=int(flask.request.form['tag']), state=None)
        return flask.redirect('/domain/'+domain)
    try: return flask.redirect('/domain/'+flask.request.values.get('domain'), code='302')
    except: pass
    #tagged_domain, domain_tags = domains.get_domain_tags(domain)
    tagged_domain = domains.get_tagged_domain(domain)
    if tagged_domain == domain:
        tagged_domain = None
    # JOIN ... WHERE ... vs WHERE id IN (... WHERE ...)
    #domain_tags = domains.Tag.select().where(domains.Tag.id<<domains.DomainTag.select(domains.DomainTag.tag).where(domains.DomainTag.domain==domains.Domain.select(domains.Domain.id).where(domains.Domain.name==domain)))
    domain_tags = domains.DomainTag.select(domains.DomainTag.state, domains.DomainTag.tag, domains.Tag.name).join(domains.Domain).join(domains.Tag, on=domains.DomainTag.tag==domains.Tag.id).where(domains.Domain.name==domain).order_by(domains.Tag.name)
    other_tags = domains.Tag.select().where(~(domains.Tag.id<<domains.DomainTag.select(domains.DomainTag.tag).where(domains.DomainTag.domain==domains.Domain.select(domains.Domain.id).where(domains.Domain.name==domain)))).order_by(domains.Tag.name)
    if flask_login.current_user.is_authenticated:
        domain_allowed = domains.domain_allowed_for_client(domain, flask_login.current_user)
    else:
        domain_allowed = domains.domain_allowed_for_client(domain)
    return flask.render_template('domain.htm', domain=domain, tagged_domain=tagged_domain, domain_tags=domain_tags, other_tags=other_tags, domain_allowed=domain_allowed)

# switch client tags, policies, update ip
# splitted into two form processing and single view function
@app.route('/settings/filtering', methods=['POST'])
@flask_login.login_required
def settings_filtering():
    request_tags = [int(tag_id) for tag_id in flask.request.form.getlist('forbidden_tag')]
    # add request tags to client forbidden tags if not yet there
    for tag_id in flask.request.form.getlist('forbidden_tag'):
        domains.ClientForbiddenTag.get_or_create(client=flask_login.current_user.id, tag=domains.Tag.get(id=int(tag_id)))
    # delete client forbidden tags which are not in request
    domains.ClientForbiddenTag.delete().where(domains.ClientForbiddenTag.client==flask_login.current_user.id, ~(domains.ClientForbiddenTag.tag<<request_tags)).execute()
    # policies
    for setting in ['allow_untagged', 'allow_mixed']:
        setattr(flask_login.current_user, setting, False if setting in flask.request.form.getlist('false') else True)
    flask_login.current_user.save()
    return flask.redirect('/settings')

@app.route('/settings/networks', methods=['POST'])
@flask_login.login_required
def settings_networks():
    if 'addr' in flask.request.form:
        addr_int = domains.addr_ddn_to_int(flask.request.form['addr'])
        client_net = domains.ClientNet.get_or_create(client=flask_login.current_user.id, name=flask.request.form['name'], defaults={'addr': addr_int})[0]
        if client_net.addr != addr_int:
            client_net.addr = addr_int
            client_net.save()
    else: # removal request
        domains.ClientNet.delete().where(domains.ClientNet.client==flask_login.current_user.id, domains.ClientNet.name==flask.request.form['name']).execute()
    return flask.redirect('/settings')

@app.route('/settings')
@flask_login.login_required
def settings():
    return flask.render_template(
        'settings.htm',
        tags=domains.Tag.select().order_by(domains.Tag.name),
        forbidden_tags=domains.Tag.select().where(domains.Tag.id<<domains.ClientForbiddenTag.select(domains.ClientForbiddenTag.tag).where(domains.ClientForbiddenTag.client==flask_login.current_user.id)),
        remote_addr=flask.request.remote_addr,
        client_nets=domains.ClientNet.select().where(domains.ClientNet.client==flask_login.current_user.id)
    )

# login/logout
@app.route('/login', methods=['GET', 'POST'])
def login():
    if flask.request.method == 'POST':
        user = check_auth(flask.request.form['username'], flask.request.form['password'])
        if user is not None:
            flask_login.login_user(user)
            return flask.redirect('/settings')
        return flask.redirect('/login')
    return flask.render_template('login.htm')

@app.route('/logout')
def logout():
    flask_login.logout_user()
    return flask.redirect('/login')

# update ip using dyndns2 protocol
# https://{user}:{updater client key}@members.dyndns.org/nic/update?hostname={hostname}&myip={IP Address}
@app.route('/nic/update') # ddclient defaults 'script' to '/nic/update'
def updateip():
    if request.authorization and check_auth(request.authorization.username, request.authorization.password):
        domains.ClientNet.update(name=request.hostname, addr=request.remote_addr).where(domains.ClientNet.client==current_user.id, name=request.hostname)
        return 'good'
    return 'badauth'

@app.route('/static/<path:path>')
def serve_static(path):
    return send_from_directory('static', path)

if __name__ == '__main__':
      app.run(host='0.0.0.0', port=80)
