import os
import json
from app import app
from flask import render_template,redirect,request, jsonify, session, flash
from werkzeug import secure_filename
from flask_sqlalchemy import SQLAlchemy
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///junky.db'
app.secret_key = 'sdsdsdsds'
db = SQLAlchemy(app)
from app.junkFiles import Junky, makeList
from app.organize import organize_junk
import json

from pathlib import Path
from app.predict import predict

class JunkExt(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    extension = db.Column(db.String(10), unique=True, nullable=False)

    def __repr__(self):
        return '<User %r>' % self.extension

class JunkReport(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    path = db.Column(db.String(30), nullable = False)
    scannedJunk = db.Column(db.String(200), nullable = False)

    def __repr__(self):
        return '<User %r>' % self.extension

class MalwareReport(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    path = db.Column(db.String(30), nullable = False)
    malicious = db.Column(db.String(200), nullable = False)

    def __repr__(self):
        return '<User %r>' % self.extension

class FileReport(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(30), nullable = False)
    malware = db.Column(db.Boolean, nullable = False)
    junk = db.Column(db.Boolean, nullable = False)

    def __repr__(self):
        return '<User %r>' % self.extension

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    password = db.Column(db.String(20), nullable=False)
    email = db.Column(db.String(20), unique=True, nullable=False)

    def __repr__(self):
        return '<User %r>' % self.extension

db.create_all()
pathDetails = {}
pathDetails['currentpath'] = ''
app.config['UPLOAD_FOLDER'] = './uploads'
junky = Junky(makeList(JunkExt.query.all()))


@app.route('/')
@app.route('/index')
def index():
    return render_template('index.html',title='home', loggedin = session.get('user'))


@app.route('/browser',methods=['get','post'])
def folder_scan_inint():
    if not session.get('user'):
        return redirect('/login')
    if request.method == 'POST':
        drive = request.form.get('drive')
        
        return render_template('browser.html')
    return render_template('browser.html')



@app.route('/browser3',methods=['get','post'])
def folder_organize_inint():
    if not session.get('user'):
        return redirect('/login')
    if request.method == 'POST':
        drive = request.form.get('drive')
        
        return render_template('organize.html')
    return render_template('organize.html')

@app.route('/uploadfile')
def getfile():
    
    return render_template('uploadfile.html')

@app.route('/scanfile', methods=["POST", "GET"])
def scanFile():
    if not session.get('user'):
        return redirect('/login')
    if request.method == 'POST':
        status = {}
        myfile = request.files.get('myfile')
        if myfile:
            filename = secure_filename(myfile.filename)
            print(filename)
            myfile.save(os.path.join(app.config['UPLOAD_FOLDER'],filename))
            status['junk'] = junky.findJunk(filename)
            if filename.endswith('exe'):
                status['malware'] = predict(f'./uploads/{filename}', './app/classifier/classifier.pkl', './app/classifier/feature.pkl') == 'malicious'
            else:
                status['malware'] = False
            
            filerep = FileReport(name = filename, malware = bool(status['malware']), junk = bool(status['junk']))
            db.session.add(filerep)
            db.session.commit()

        return render_template('filescanresults.html', status = status)
    return redirect('/')

# @app.route('/browser/<path:urlFilePath>')
# def browser(urlFilePath):
    
#     FILE_SYSTEM_ROOT = os.getcwd()
#     nestedFilePath = os.path.join(FILE_SYSTEM_ROOT, urlFilePath)
#     nestedFilePath = nestedFilePath.replace("/", "\\")
#     if os.path.realpath(nestedFilePath) != nestedFilePath:
#         return "no directory traversal please."
#     if os.path.isdir(nestedFilePath):
#         itemList = os.listdir(nestedFilePath)
#         fileProperties = {"filepath": nestedFilePath}
#         if not urlFilePath.startswith("/"):
#             urlFilePath = "/" + urlFilePath
#         return render_template('browse.html', urlFilePath=urlFilePath, itemList=itemList)
#     if os.path.isfile(nestedFilePath):
#         fileProperties = {"filepath": nestedFilePath}
#         sbuf = os.fstat(os.open(nestedFilePath, os.O_RDONLY)) #Opening the file and getting metadata
#         fileProperties['type'] = stat.S_IFMT(sbuf.st_mode) 
#         fileProperties['mode'] = stat.S_IMODE(sbuf.st_mode) 
#         fileProperties['mtime'] = sbuf.st_mtime 
#         fileProperties['size'] = sbuf.st_size 
#         if not urlFilePath.startswith("/"):
#             urlFilePath = "/" + urlFilePath
#         return render_template('filedetail.html', currentFile=nestedFilePath, fileProperties=fileProperties)
#     return 'something bad happened'
    

@app.route('/dir')
def getFolders():
    path = request.args.get('path')
    dirList = []
    try:
        if(path == '..'):
            pathDetails['currentpath'], lastdir = os.path.split(pathDetails['currentpath'])
        else:
            pathDetails['currentpath'] = os.path.join(pathDetails['currentpath'], path)
            # print(pathDetails)

        dirList = os.listdir(pathDetails['currentpath'])
        # for path in dirList:
        #     print(os.path.join(pathDetails['currentpath'],path))
        dirList = [path for path in dirList if os.path.isdir(os.path.join(pathDetails['currentpath'],path))]
        session['currentdir'] = pathDetails['currentpath']
        return jsonify([dirList, pathDetails['currentpath']])
    
    except Exception as e:
        print('an error occured!!')
        print(e)
        pathDetails['currentpath'], lastdir = os.path.split(pathDetails['currentpath'])
        return jsonify(None)
    
@app.route('/organize')
def organize():
    path = request.args.get('path')
    print(path)
    organize_junk(path)
    return jsonify('success')

@app.route('/ext')
def extensions():
    if not session.get('user'):
        return redirect('/login')
    return render_template('extensions.html')

@app.route('/addext')
def addExt():
    ext = request.args.get('ext')
    jun = JunkExt(extension = ext)

    db.session.add(jun)
    db.session.commit()
    return jsonify('success')

@app.route('/getext')
def getExtensions():
    allext = JunkExt.query.all()
    return jsonify(makeList(allext))

@app.route('/delext')
def deleteExtensions():
    ext = JunkExt.query.filter_by(extension = request.args.get('name')).first()
    if ext:
        db.session.delete(ext)
        db.session.commit()
        return jsonify('extension deleted!!')
    
    else:
        return jsonify('not extension found')
    

@app.route('/scanJunk')
def scanJunk():
    if not session.get('user'):
        return redirect('/login')
    nofiles = True
    path = request.args.get('path')
    junkFiles = scanForJunk(path)
    print(junkFiles)
    junkreport = JunkReport(path = path, scannedJunk = ', '.join(junkFiles))

    try:
        db.session.add(junkreport)
        db.session.commit()
    
    except Exception as e:
        print("couldn't save report")
        print(e)

    if junkFiles:
        nofiles = False
    session['junkpath'] = path
    junExts = [name.split('.')[-1] for name in junkFiles]
    return render_template('scanJunkList.html', data = zip(junkFiles,junExts), nofiles = nofiles)

@app.route('/browsemalware')
def browseMalware():
    if not session.get('user'):
        return redirect('/login')
    return render_template('browseMalware.html')

@app.route('/scanMalware')
def scanMalware():
    if not session.get('user'):
        return redirect('/login')
    nofiles = True
    path = request.args.get('path')
    print(path)
    scanData = scanForMalware(path)
    print(scanData)
    mal_files = []
    for key, value in list(scanData.items())[1:]:
        if value == 'malicious':
            mal_files.append(key)
    
    malreport = MalwareReport(path = scanData['path'], malicious = ', '.join(mal_files))

    try:
        db.session.add(malreport)
        db.session.commit()
    
    except Exception as e:
        print("couldn't save report")
        print(e)
    if mal_files:
        nofiles = False
    session['junkpath'] = path
    # junExts = [name.split('.')[-1] for name in junkFiles]
    return jsonify({'path' : list(scanData.items())[0][1], 'files' : list(scanData.items())[1:]})
    # return render_template('scanMalwareList.html', path = list(scanData.items())[0][1], files = list(scanData.items())[1:])

@app.route('/showmal')
def showMalList():
    return render_template('scanMalwareList.html')


def scanForMalware(folder):
    if folder:
        pathlist=list(Path(folder).glob('**/*.exe'))+list(Path(folder).glob('**/*.dll'))
        results={}
        results['path']=folder
        print(folder)
        for path in pathlist:
            base=os.path.basename(path)
            
            results[base]=predict(path, os.path.join(os.path.dirname(os.path.realpath(__file__)),'classifier/classifier.pkl'), os.path.join(os.path.dirname(os.path.realpath(__file__)),'classifier/feature.pkl'))
        return (results)

def scanForJunk(path):
    return junky.getJunkFiles(path)



@app.route('/delMalware', methods=['GET', 'POST'])
def delJunk():
    path = request.args.get('path')
    files = json.loads(request.args.get('files'))
    
    try:
        for f in [file[0] for file in files if file[1] == 'malicious']:
            print(os.path.join(path, f))
            os.remove(os.path.join(path, f)) 
        return jsonify('success')
    except Exception as e:
        print('Error occured', e)
        return jsonify('Error occured')

@app.route('/delJunk', methods=['GET', 'POST'])
def delMalware():
    path = session.get('path')
    files = session.get('maliousFiles')
    if not files:
        return jsonify('files not found!!')
    else:
        dirList = scanForJunk(path)
        print('list', dirList)
        try:
            for f in dirList:
                print(f)
                os.remove(os.path.join(path, f))
            return jsonify('success')
        except Exception as e:
            print('Error occured', e)
            return jsonify('Error occured')


@app.route('/login', methods=['GET', 'POST'] )
def login():
    # messages = {}
    if request.method == 'POST':
        form = request.form
        user = User.query.filter_by(username=form.get('username')).first()
        if user:
            if user.password == form.get('password'):
                session['user'] = user.username
                return redirect('/')
            else:
                print('password incorrect')
                flash('Username or password invalid')
        else:
            print('username not found')
            flash('Username or password invalid')
            # messages['error'] = 'Username or password invalid'
    return render_template('login.html')
    
@app.route('/logout')
def logout():
    session['user'] = None
    return redirect('/login')

@app.route('/signup', methods=['GET', 'POST'] )
def signup():
    if request.method == 'POST':
        form = request.form
        try:
            user = User(username = form.get('username'), password = form.get('password'), email = form.get('email'))
            db.session.add(user)
            db.session.commit()
        except Exception as e:
            print('could not sign up')
            print(e)
            return render_template('login.html')
        
    return render_template('login.html')



@app.route('/reportdash')
def reportDashboard():
    if not session.get('user'):
        return redirect('/login')
    print(session.get('user'))
    return render_template('reportdash.html')
    
@app.route('/junkreport')
def junkReport():
    if not session.get('user'):
        return redirect('/login')
    data = JunkReport.query.all()
    return render_template('junkreport.html', data = data)
        
@app.route('/malreport')
def malwareReport():
    if not session.get('user'):
        return redirect('/login')
    data = MalwareReport.query.all()
    return render_template('malwarereport.html', data = data)

@app.route('/filereport')
def fileReport():
    if not session.get('user'):
        return redirect('/login')
    data = FileReport.query.all()
    return render_template('filereport.html', data = data)
