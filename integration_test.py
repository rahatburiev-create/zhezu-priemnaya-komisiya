"""End-to-end checks using a temporary JSON text database; no real user data."""
import concurrent.futures, http.client, json, os, pathlib, secrets, shutil, socket, subprocess, tempfile, time
ROOT = pathlib.Path(__file__).resolve().parents[1]
JAVA = ['node', str(ROOT/'server.js')]
passed = 0

def check(value, label):
    global passed
    if not value: raise AssertionError(label)
    passed += 1

def req(path, method='GET', data=None, cookie='', origin=True, raw=None, ctype='application/json'):
    conn = http.client.HTTPConnection('127.0.0.1', PORT, timeout=20)
    headers = {}
    if origin: headers['Origin'] = ORIGIN if origin is True else origin
    if cookie: headers['Cookie'] = cookie
    body = raw if raw is not None else (json.dumps(data, ensure_ascii=False).encode() if data is not None else None)
    if body is not None: headers['Content-Type'] = ctype
    conn.request(method, path, body, headers)
    response = conn.getresponse(); payload = response.read(); status = response.status; h = dict(response.getheaders());conn.close()
    try: result = json.loads(payload)
    except Exception: result = payload.decode('utf-8', errors='replace')
    return status, result, h

def session(headers): return headers['Set-cookie' if 'Set-cookie' in headers else 'Set-Cookie'].split(';')[0]

with tempfile.TemporaryDirectory(prefix='zhezu-text-check-') as temp:
    db = pathlib.Path(temp)/'database.txt'
    password = secrets.token_urlsafe(20)
    shutil.copyfile(ROOT/'database.txt',db)
    setup = subprocess.run(JAVA+['--setup-admin','--db',str(db),'--login','commission.test','--password-stdin'],input=password+'\n',text=True,capture_output=True)
    check(setup.returncode == 0, 'admin creation: '+setup.stderr)
    with socket.socket() as sock: sock.bind(('127.0.0.1',0));PORT=sock.getsockname()[1]
    ORIGIN = 'http://127.0.0.1:'+str(PORT)
    logfile=open(pathlib.Path(temp)/'server.log','w')
    def start():
        proc=subprocess.Popen(JAVA+['--db',str(db),'--port',str(PORT)],stdout=logfile,stderr=logfile)
        for _ in range(100):
            try:
                if req('/api/auth/me')[0] == 200:return proc
            except OSError:pass
            if proc.poll() is not None:raise RuntimeError('Server did not start')
            time.sleep(.05)
        raise RuntimeError('Server startup timeout')
    proc=start()
    try:
        check(req('/')[0]==200,'public homepage')
        programs=req('/api/programs')[1]['programs']
        check(len(programs)==21 and sum(p['level']=='bachelor' for p in programs)==18,'all flyer programs')
        check(sum(p['level']=='master' for p in programs)==3,'master programs')
        check(req('/api/auth/me')[1]['user'] is None,'anonymous identity')
        for p in ['/api/admin/applicants','/api/admin/tasks','/api/admin/export','/api/my/applications']:
            check(req(p)[0]==401,'anonymous denied '+p)
        check(req('/admin.html')[0]==303,'admin HTML anonymous redirect')
        for p in ['/database.txt','/../database.txt','/%2e%2e/database.txt','/server.js']:
            check(req(p)[0]==404,'private file hidden '+p)
        check(req('/api/auth/register','POST',{'name':'Test','login':'role.test','password':password,'role':'admin'})[0]==400,'registration role injection denied')
        check(req('/api/auth/register','POST',{'name':'Test','login':'short.test','password':'short'})[0]==400,'weak password rejected')
        check(req('/api/auth/login','POST',{'login':'commission.test','password':password},origin='https://invalid.example')[0]==403,'cross origin denied')
        check(req('/api/auth/login','POST',{'login':'commission.test','password':password},origin=False)[0]==403,'missing origin denied')
        check(req('/api/auth/login','POST',raw=b'a'*17000)[0]==413,'body limit enforced')
        check(req('/api/auth/login','POST',raw=b'{}',ctype='text/plain')[0]==415,'content type enforced')
        check(req('/api/auth/login','POST',{'login':'commission.test','password':'wrong'})[0]==401,'bad password denied')
        status,body,headers=req('/api/auth/register','POST',{'name':'Student One','login':'student.one','password':password})
        student=session(headers);check(status==201 and body['user']['role']=='student','registration fixed student role')
        cookie_header=next(v for k,v in headers.items() if k.lower()=='set-cookie')
        check('HttpOnly' in cookie_header and 'SameSite=Strict' in cookie_header,'cookie protections')
        check(req('/api/auth/register','POST',{'name':'Duplicate','login':'STUDENT.ONE','password':password})[0]==409,'case insensitive unique login')
        for p in ['/api/admin/applicants','/api/admin/tasks','/api/admin/export']:
            check(req(p,cookie=student)[0]==403,'student private endpoint denied '+p)
        check(req('/admin.html',cookie=student)[0]==403,'student admin HTML denied')
        check(req('/api/admin/applicants','POST',{'name':'Wrong'},student)[0]==403,'student admin write denied')
        inquiry={'name':'Student One','phone':'','email':'student@example.invalid','program':'','programId':'M02','message':'Test inquiry','consent':True}
        check(req('/api/inquiries','POST',{**inquiry,'note':'private injection'},student)[0]==400,'inquiry privilege fields denied')
        check(req('/api/inquiries','POST',{**inquiry,'consent':False},student)[0]==400,'consent required')
        status,body,_=req('/api/inquiries','POST',inquiry,student);app_id=body['reference'];check(status==201,'inquiry saved to text database')
        own=req('/api/my/applications',cookie=student)[1]['applications']
        check(len(own)==1 and own[0]['level']=='Магистратура','own application and correct level')
        check('note' not in own[0] and 'passwordHash' not in own[0] and 'userId' not in own[0],'student output minimization')
        _,_,headers=req('/api/auth/register','POST',{'name':'Student Two','login':'student.two','password':password})
        student2=session(headers)
        check(req('/api/my/applications',cookie=student2)[1]['applications']==[],'other student sees no records')
        status,body,headers=req('/api/auth/login','POST',{'login':'COMMISSION.TEST','password':password});admin=session(headers)
        check(status==200 and body['user']['role']=='admin','database admin login')
        check(req('/admin.html',cookie=admin)[0]==200,'authorized admin page')
        check(req('/api/admin/applicants',cookie=admin)[1]['applicants'][0]['id']==app_id,'admin reads real record')
        def patch(values):return req('/api/admin/applicants/'+app_id,'PATCH',values,admin)[0]
        with concurrent.futures.ThreadPoolExecutor(2) as pool: results=list(pool.map(patch,[{'status':'review'},{'note':'Internal note'}]))
        record=req('/api/admin/applicants',cookie=admin)[1]['applicants'][0]
        check(results==[200,200] and record['status']=='review' and record['note']=='Internal note','concurrent partial updates preserved')
        own=req('/api/my/applications',cookie=student)[1]['applications'][0]
        check(own['status']=='review' and 'note' not in own,'status shared but notes private')
        status,body,_=req('/api/admin/tasks','POST',{'title':'Meeting test','kind':'meeting','dueAt':'','done':False},admin);task_id=body['task']['id']
        check(status==201,'task create')
        check(req('/api/admin/tasks/'+task_id,'PATCH',{'done':True},admin)[1]['task']['done'] is True,'task update')
        status,csv,_=req('/api/admin/export',cookie=admin);check(status==200 and 'Student One' in csv,'protected CSV export')
        lock=subprocess.run(JAVA+['--db',str(db),'--port',str(PORT)],capture_output=True,timeout=20)
        check(lock.returncode!=0,'second writer process refused')
        proc.terminate();proc.wait(timeout=15);proc=start()
        check(req('/api/auth/me',cookie=student)[1]['user']['login']=='student.one','session persisted in text database after restart')
        check(req('/api/my/applications',cookie=student)[1]['applications'][0]['id']==app_id,'records persisted after restart')
        check(req('/api/admin/tasks',cookie=admin)[1]['tasks'][0]['done'] is True,'task persistence')
        check(req('/api/auth/logout','POST',{},student)[0]==200 and req('/api/my/applications',cookie=student)[0]==401,'logout invalidates stored session')
        check(req('/api/admin/tasks/'+task_id,'DELETE',{},admin)[0]==200,'task delete')
        check(req('/api/admin/applicants/'+app_id,'DELETE',{},admin)[0]==200,'applicant delete')
    finally:
        proc.terminate();proc.wait(timeout=15);logfile.close()
print('PASS:',passed,'integration checks using a temporary JSON text database')
