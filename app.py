import streamlit as st
import sqlite3, hashlib, secrets, string, io
from datetime import datetime, timedelta
from pathlib import Path
from contextlib import contextmanager

try:
    import qrcode
except Exception:
    qrcode = None

APP_NAME = "SGD-I"
DB_PATH = Path("sgdi.db")
UPLOAD_DIR = Path("data_uploads")
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
MAX_UPLOAD_MB = 50

st.set_page_config(page_title="SGD-I | Gestión Documental Industrial", page_icon="🏭", layout="wide", initial_sidebar_state="expanded")

st.markdown("""
<style>
.stApp{background:#fbf7ed;color:#2b2112}
[data-testid="stSidebar"]{background:#241b0d}
[data-testid="stSidebar"] *{color:#fff!important}
.main-title{background:linear-gradient(100deg,#3a290b,#8f6b12,#D4AF37,#f4dc8a);padding:24px;border-radius:16px;color:white;margin-bottom:20px;box-shadow:0 8px 25px rgba(90,66,22,.18)}
.card{background:#fffdf8;border:1px solid #dfc879;border-radius:14px;padding:16px;margin-bottom:12px}
.alert-card{background:#fff7d6;border-left:6px solid #D4AF37;padding:14px;border-radius:10px;margin-bottom:10px}
.danger-card{background:#fff0ed;border-left:6px solid #b42318;padding:14px;border-radius:10px;margin-bottom:10px}
.success-card{background:#edf9f0;border-left:6px solid #16803c;padding:14px;border-radius:10px;margin-bottom:10px}
</style>
""", unsafe_allow_html=True)

DEPARTMENTS=["Diseño / Preimpresión","Producción / Flexografía","Control de Calidad","Mantenimiento","Logística","Compras","Administración","Gerencia"]
ROLES=["ADMINISTRADOR","JEFE_PRODUCCION","OPERARIO","DISEÑADOR","CALIDAD","MANTENIMIENTO","LOGISTICA","COMPRAS","ADMINISTRACION","AUDITOR"]
SUPERVISOR_ROLES={"ADMINISTRADOR","GERENCIA","JEFE_PRODUCCION","CALIDAD","AUDITOR"}
DOC_TYPES=["Procedimiento","Instructivo","Formato","Registro","Orden de producción","Ficha técnica","Arte final","Control de calidad","Certificado de materia prima","RNC","Acción correctiva","Mantenimiento","Albarán","Informe","Checklist","Otro"]
DOC_STATUSES=["BORRADOR","EN_REVISION","OBSERVADO","APROBADO","VIGENTE","OBSOLETO","ARCHIVADO"]
REVIEW_STATES=["SIN_REVISAR","EN_REVISION","REVISADO","APROBADO","OBSERVADO"]
JOB_STATUSES=["PENDIENTE","EN_PROCESO","PENDIENTE_SUPERVISION","COMPLETADO","APROBADO","RECHAZADO"]

@contextmanager
def db():
    conn=sqlite3.connect(DB_PATH)
    conn.row_factory=sqlite3.Row
    conn.execute("PRAGMA foreign_keys=ON")
    try:
        yield conn; conn.commit()
    except Exception:
        conn.rollback(); raise
    finally: conn.close()

def now(): return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def hash_password(password):
    salt=secrets.token_bytes(16)
    digest=hashlib.pbkdf2_hmac("sha256",password.encode(),salt,120000)
    return f"pbkdf2_sha256$120000${salt.hex()}${digest.hex()}"

def verify_password(password,stored):
    try:
        algo,iters,salt_hex,digest_hex=stored.split("$")
        if algo!="pbkdf2_sha256": return False
        calc=hashlib.pbkdf2_hmac("sha256",password.encode(),bytes.fromhex(salt_hex),int(iters)).hex()
        return secrets.compare_digest(calc,digest_hex)
    except Exception: return False

def hash_key(key): return hashlib.sha256(key.encode()).hexdigest()

def make_code(prefix): return f"{prefix}-{datetime.now():%Y%m%d}-{secrets.token_hex(3).upper()}"

def safe_filename(name): return "".join(c if c.isalnum() or c in "._-" else "_" for c in Path(name).name)

def audit(user_id,action,entity,entity_id="",details=""):
    with db() as conn:
        conn.execute("INSERT INTO audit_log(user_id,action,entity,entity_id,details,created_at) VALUES(?,?,?,?,?,?)",(user_id,action,entity,str(entity_id),details,now()))

def table_columns(conn,table): return {r[1] for r in conn.execute(f"PRAGMA table_info({table})").fetchall()}

def init_db():
    with db() as conn:
        conn.executescript("""
        CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY AUTOINCREMENT,username TEXT UNIQUE NOT NULL,full_name TEXT NOT NULL,password_hash TEXT NOT NULL,role TEXT NOT NULL,department TEXT NOT NULL,active INTEGER NOT NULL DEFAULT 1,created_at TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS projects(id INTEGER PRIMARY KEY AUTOINCREMENT,code TEXT UNIQUE NOT NULL,name TEXT NOT NULL,description TEXT,department TEXT,manager_id INTEGER,status TEXT DEFAULT 'ACTIVO',created_at TEXT NOT NULL,FOREIGN KEY(manager_id) REFERENCES users(id));
        CREATE TABLE IF NOT EXISTS documents(id INTEGER PRIMARY KEY AUTOINCREMENT,code TEXT UNIQUE NOT NULL,title TEXT NOT NULL,department TEXT NOT NULL,project_id INTEGER,document_type TEXT NOT NULL,filename TEXT NOT NULL,stored_path TEXT NOT NULL,status TEXT NOT NULL DEFAULT 'BORRADOR',review_status TEXT NOT NULL DEFAULT 'SIN_REVISAR',version INTEGER NOT NULL DEFAULT 1,uploaded_by INTEGER NOT NULL,reviewed_by INTEGER,approved_by INTEGER,reviewed_at TEXT,approved_at TEXT,due_date TEXT,created_at TEXT NOT NULL,updated_at TEXT NOT NULL,FOREIGN KEY(project_id) REFERENCES projects(id),FOREIGN KEY(uploaded_by) REFERENCES users(id),FOREIGN KEY(reviewed_by) REFERENCES users(id),FOREIGN KEY(approved_by) REFERENCES users(id));
        CREATE TABLE IF NOT EXISTS document_versions(id INTEGER PRIMARY KEY AUTOINCREMENT,document_id INTEGER NOT NULL,version INTEGER NOT NULL,filename TEXT NOT NULL,stored_path TEXT NOT NULL,change_reason TEXT,uploaded_by INTEGER NOT NULL,created_at TEXT NOT NULL,FOREIGN KEY(document_id) REFERENCES documents(id),FOREIGN KEY(uploaded_by) REFERENCES users(id));
        CREATE TABLE IF NOT EXISTS document_movements(id INTEGER PRIMARY KEY AUTOINCREMENT,document_id INTEGER NOT NULL,from_department TEXT,from_project INTEGER,to_department TEXT,to_project INTEGER,movement_type TEXT NOT NULL,reason TEXT NOT NULL,user_id INTEGER NOT NULL,created_at TEXT NOT NULL,FOREIGN KEY(document_id) REFERENCES documents(id),FOREIGN KEY(user_id) REFERENCES users(id));
        CREATE TABLE IF NOT EXISTS jobs(id INTEGER PRIMARY KEY AUTOINCREMENT,job_code TEXT UNIQUE NOT NULL,title TEXT NOT NULL,description TEXT,department TEXT NOT NULL,project_id INTEGER,assigned_to INTEGER NOT NULL,supervisor_name TEXT,status TEXT NOT NULL DEFAULT 'PENDIENTE',progress INTEGER NOT NULL DEFAULT 0,due_date TEXT,created_at TEXT NOT NULL,updated_at TEXT NOT NULL,FOREIGN KEY(project_id) REFERENCES projects(id),FOREIGN KEY(assigned_to) REFERENCES users(id));
        CREATE TABLE IF NOT EXISTS job_evidence(id INTEGER PRIMARY KEY AUTOINCREMENT,job_id INTEGER NOT NULL,filename TEXT NOT NULL,stored_path TEXT NOT NULL,uploaded_by INTEGER NOT NULL,created_at TEXT NOT NULL,FOREIGN KEY(job_id) REFERENCES jobs(id),FOREIGN KEY(uploaded_by) REFERENCES users(id));
        CREATE TABLE IF NOT EXISTS supervision_keys(id INTEGER PRIMARY KEY AUTOINCREMENT,job_id INTEGER NOT NULL,employee_id INTEGER NOT NULL,key_hash TEXT NOT NULL UNIQUE,key_hint TEXT NOT NULL,expires_at TEXT NOT NULL,used INTEGER NOT NULL DEFAULT 0,created_at TEXT NOT NULL,used_at TEXT,supervisor_name TEXT,FOREIGN KEY(job_id) REFERENCES jobs(id),FOREIGN KEY(employee_id) REFERENCES users(id));
        CREATE TABLE IF NOT EXISTS supervision_history(id INTEGER PRIMARY KEY AUTOINCREMENT,job_id INTEGER NOT NULL,key_id INTEGER,supervisor_id INTEGER,decision TEXT NOT NULL,comments TEXT,created_at TEXT NOT NULL,FOREIGN KEY(job_id) REFERENCES jobs(id),FOREIGN KEY(supervisor_id) REFERENCES users(id));
        CREATE TABLE IF NOT EXISTS audit_log(id INTEGER PRIMARY KEY AUTOINCREMENT,user_id INTEGER,action TEXT NOT NULL,entity TEXT NOT NULL,entity_id TEXT,details TEXT,created_at TEXT NOT NULL,FOREIGN KEY(user_id) REFERENCES users(id));
        CREATE INDEX IF NOT EXISTS idx_docs_review ON documents(review_status); CREATE INDEX IF NOT EXISTS idx_docs_user ON documents(uploaded_by); CREATE INDEX IF NOT EXISTS idx_docs_title ON documents(title); CREATE INDEX IF NOT EXISTS idx_audit_date ON audit_log(created_at);
        """)
        cols=table_columns(conn,"documents")
        for col,definition in [("project_id","INTEGER"),("version","INTEGER NOT NULL DEFAULT 1"),("review_status","TEXT NOT NULL DEFAULT 'SIN_REVISAR'"),("reviewed_by","INTEGER"),("approved_by","INTEGER"),("reviewed_at","TEXT"),("approved_at","TEXT"),("due_date","TEXT"),("updated_at","TEXT")]:
            if col not in cols: conn.execute(f"ALTER TABLE documents ADD COLUMN {col} {definition}")
        u=conn.execute("SELECT id FROM users WHERE username='Mariana'").fetchone(); legacy=conn.execute("SELECT id FROM users WHERE username='admin'").fetchone()
        if not u and legacy:
            conn.execute("UPDATE users SET username='Mariana',full_name='Mariana',password_hash=?,role='ADMINISTRADOR',department='Gerencia',active=1 WHERE id=?",(hash_password("Mariana0526*"),legacy["id"]))
        elif not u:
            conn.execute("INSERT INTO users(username,full_name,password_hash,role,department,created_at) VALUES(?,?,?,?,?,?)",("Mariana","Mariana",hash_password("Mariana0526*"),"ADMINISTRADOR","Gerencia",now()))
        else:
            conn.execute("UPDATE users SET full_name='Mariana',password_hash=?,role='ADMINISTRADOR',department='Gerencia',active=1 WHERE username='Mariana'",(hash_password("Mariana0526*"),))

def authenticate(username,password):
    with db() as conn:
        row=conn.execute("SELECT * FROM users WHERE username=? AND active=1",(username.strip(),)).fetchone()
        return row if row and verify_password(password,row["password_hash"]) else None

def get_users(active_only=False):
    with db() as conn:
        sql="SELECT * FROM users"+(" WHERE active=1" if active_only else "")+" ORDER BY full_name COLLATE NOCASE, username COLLATE NOCASE"
        return conn.execute(sql).fetchall()

def create_user(username,full_name,password,role,department):
    if not username.strip() or not full_name.strip() or len(password)<8: raise ValueError("Complete los datos y use una contraseña de al menos 8 caracteres.")
    with db() as conn: conn.execute("INSERT INTO users(username,full_name,password_hash,role,department,created_at) VALUES(?,?,?,?,?,?)",(username.strip(),full_name.strip(),hash_password(password),role,department,now()))

def set_user_active(uid,active,actor):
    with db() as conn: conn.execute("UPDATE users SET active=? WHERE id=?",(1 if active else 0,uid))
    audit(actor,"ACTIVAR_USUARIO" if active else "DESACTIVAR_USUARIO","USER",uid,"")

def get_projects():
    with db() as conn: return conn.execute("SELECT p.*,u.full_name AS manager FROM projects p LEFT JOIN users u ON u.id=p.manager_id ORDER BY p.name COLLATE NOCASE").fetchall()

def create_project(name,description,department,manager_id):
    code=make_code("PROY")
    with db() as conn: conn.execute("INSERT INTO projects(code,name,description,department,manager_id,created_at) VALUES(?,?,?,?,?,?)",(code,name.strip(),description.strip(),department,manager_id,now()))
    return code

def create_document(uploaded,title,department,doc_type,user_id,project_id=None,due_date=None):
    if uploaded is None: raise ValueError("Seleccione un archivo.")
    if uploaded.size>MAX_UPLOAD_MB*1024*1024: raise ValueError(f"El archivo supera {MAX_UPLOAD_MB} MB.")
    code=make_code("DOC"); original=Path(uploaded.name).name; safe=safe_filename(original); dest=UPLOAD_DIR/f"{code}_v1_{safe}"; dest.write_bytes(uploaded.getbuffer())
    with db() as conn:
        conn.execute("INSERT INTO documents(code,title,department,project_id,document_type,filename,stored_path,status,review_status,version,uploaded_by,due_date,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)",(code,title.strip(),department,project_id,doc_type,original,str(dest),"BORRADOR","SIN_REVISAR",1,user_id,due_date,now(),now()))
        did=conn.execute("SELECT id FROM documents WHERE code=?",(code,)).fetchone()["id"]
        conn.execute("INSERT INTO document_versions(document_id,version,filename,stored_path,change_reason,uploaded_by,created_at) VALUES(?,?,?,?,?,?,?)",(did,1,original,str(dest),"Versión inicial",user_id,now()))
    audit(user_id,"CARGAR_DOCUMENTO","DOCUMENT",code,f"Archivo={original};Departamento={department};Tipo={doc_type}"); return code

def get_documents(sort_by="Nombre",department=None,review=None):
    order={"Nombre":"d.title COLLATE NOCASE ASC,d.created_at DESC","Usuario":"u.full_name COLLATE NOCASE ASC,d.title COLLATE NOCASE ASC","Más recientes":"d.created_at DESC","Estado":"d.review_status ASC,d.title COLLATE NOCASE ASC","Versión":"d.version DESC,d.title COLLATE NOCASE ASC"}.get(sort_by,"d.title COLLATE NOCASE ASC")
    where=[]; params=[]
    if department and department!="Todos": where.append("d.department=?"); params.append(department)
    if review and review!="Todos": where.append("d.review_status=?"); params.append(review)
    sql=f"SELECT d.*,u.full_name AS uploader,p.name AS project_name,rv.full_name AS reviewer,av.full_name AS approver FROM documents d JOIN users u ON u.id=d.uploaded_by LEFT JOIN projects p ON p.id=d.project_id LEFT JOIN users rv ON rv.id=d.reviewed_by LEFT JOIN users av ON av.id=d.approved_by"+((" WHERE "+" AND ".join(where)) if where else "")+f" ORDER BY {order}"
    with db() as conn: return conn.execute(sql,params).fetchall()

def get_document(did):
    with db() as conn: return conn.execute("SELECT d.*,u.full_name AS uploader,p.name AS project_name FROM documents d JOIN users u ON u.id=d.uploaded_by LEFT JOIN projects p ON p.id=d.project_id WHERE d.id=?",(did,)).fetchone()

def mark_review(did,uid,state="REVISADO"):
    with db() as conn: conn.execute("UPDATE documents SET review_status=?,status=?,reviewed_by=?,reviewed_at=?,updated_at=? WHERE id=?",(state,"EN_REVISION" if state=="REVISADO" else state,did and uid,now(),now(),did))
    audit(uid,"REVISAR_DOCUMENTO","DOCUMENT",did,f"Estado={state}")

def approve_document(did,uid,approve=True,comment=""):
    status="VIGENTE" if approve else "OBSERVADO"; review="APROBADO" if approve else "OBSERVADO"
    with db() as conn: conn.execute("UPDATE documents SET status=?,review_status=?,approved_by=?,approved_at=?,updated_at=? WHERE id=?",(status,review,uid,now(),now(),did))
    audit(uid,"APROBAR_DOCUMENTO" if approve else "OBSERVAR_DOCUMENTO","DOCUMENT",did,comment)

def add_document_version(did,uploaded,reason,uid):
    if uploaded is None: raise ValueError("Seleccione el nuevo archivo.")
    if uploaded.size>MAX_UPLOAD_MB*1024*1024: raise ValueError(f"El archivo supera {MAX_UPLOAD_MB} MB.")
    doc=get_document(did); newver=doc["version"]+1; safe=safe_filename(uploaded.name); dest=UPLOAD_DIR/f"{doc['code']}_v{newver}_{safe}"; dest.write_bytes(uploaded.getbuffer())
    with db() as conn:
        conn.execute("INSERT INTO document_versions(document_id,version,filename,stored_path,change_reason,uploaded_by,created_at) VALUES(?,?,?,?,?,?,?)",(did,newver,Path(uploaded.name).name,str(dest),reason.strip(),uid,now()))
        conn.execute("UPDATE documents SET version=?,filename=?,stored_path=?,review_status='SIN_REVISAR',status='BORRADOR',uploaded_by=?,updated_at=? WHERE id=?",(newver,Path(uploaded.name).name,str(dest),uid,now(),did))
    audit(uid,"NUEVA_VERSION","DOCUMENT",did,f"Versión={newver};Motivo={reason}")

def move_document(did,to_department,to_project,reason,uid):
    doc=get_document(did)
    with db() as conn:
        conn.execute("INSERT INTO document_movements(document_id,from_department,from_project,to_department,to_project,movement_type,reason,user_id,created_at) VALUES(?,?,?,?,?,?,?,?,?)",(did,doc["department"],doc["project_id"],to_department,to_project,"TRANSFERENCIA",reason.strip(),uid,now()))
        conn.execute("UPDATE documents SET department=?,project_id=?,updated_at=? WHERE id=?",(to_department,to_project,now(),did))
    audit(uid,"MOVER_DOCUMENTO","DOCUMENT",did,f"De={doc['department']} a={to_department};Motivo={reason}")

def document_history(did):
    with db() as conn:
        versions=conn.execute("SELECT v.*,u.full_name AS user_name FROM document_versions v JOIN users u ON u.id=v.uploaded_by WHERE v.document_id=? ORDER BY v.version DESC",(did,)).fetchall()
        movements=conn.execute("SELECT m.*,u.full_name AS user_name,p1.name AS from_project_name,p2.name AS to_project_name FROM document_movements m JOIN users u ON u.id=m.user_id LEFT JOIN projects p1 ON p1.id=m.from_project LEFT JOIN projects p2 ON p2.id=m.to_project WHERE m.document_id=? ORDER BY m.created_at DESC",(did,)).fetchall()
    return versions,movements

def alerts():
    with db() as conn:
        recent=conn.execute("SELECT d.*,u.full_name AS uploader FROM documents d JOIN users u ON u.id=d.uploaded_by ORDER BY d.created_at DESC LIMIT 30").fetchall()
        unreviewed=conn.execute("SELECT d.*,u.full_name AS uploader FROM documents d JOIN users u ON u.id=d.uploaded_by WHERE d.review_status='SIN_REVISAR' ORDER BY d.created_at ASC").fetchall()
        today=datetime.now().date(); soon=(today+timedelta(days=7)).isoformat()
        due=conn.execute("SELECT d.*,u.full_name AS uploader FROM documents d JOIN users u ON u.id=d.uploaded_by WHERE d.due_date IS NOT NULL AND d.due_date<=? AND d.status NOT IN ('OBSOLETO','ARCHIVADO') ORDER BY d.due_date",(soon,)).fetchall()
    return recent,unreviewed,due

def create_job(title,description,department,project_id,assigned_to,due_date):
    code=make_code("OT")
    with db() as conn: conn.execute("INSERT INTO jobs(job_code,title,description,department,project_id,assigned_to,due_date,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?)",(code,title.strip(),description.strip(),department,project_id,assigned_to,due_date,now(),now()))
    return code

def get_jobs(user=None):
    sql="SELECT j.*,u.full_name AS employee,p.name AS project_name FROM jobs j JOIN users u ON u.id=j.assigned_to LEFT JOIN projects p ON p.id=j.project_id"
    params=[]
    if user and user["role"]=="OPERARIO": sql+=" WHERE j.assigned_to=?"; params=[user["id"]]
    elif user and user["role"]=="JEFE_PRODUCCION": sql+=" WHERE j.department='Producción / Flexografía' OR j.assigned_to=?"; params=[user["id"]]
    sql+=" ORDER BY CASE WHEN j.status IN ('PENDIENTE','EN_PROCESO','PENDIENTE_SUPERVISION') THEN 0 ELSE 1 END,j.due_date IS NULL,j.due_date"
    with db() as conn: return conn.execute(sql,params).fetchall()

def update_job(jid,status,progress,uid):
    with db() as conn: conn.execute("UPDATE jobs SET status=?,progress=?,updated_at=? WHERE id=?",(status,int(progress),now(),jid))
    audit(uid,"ACTUALIZAR_TRABAJO","JOB",jid,f"Estado={status};Progreso={progress}%")

def save_job_evidence(jid,uploaded,uid):
    if uploaded is None: return
    if uploaded.size>MAX_UPLOAD_MB*1024*1024: raise ValueError("La evidencia supera 50 MB.")
    dest=UPLOAD_DIR/f"JOB-{jid}-{secrets.token_hex(4)}_{safe_filename(uploaded.name)}"; dest.write_bytes(uploaded.getbuffer())
    with db() as conn: conn.execute("INSERT INTO job_evidence(job_id,filename,stored_path,uploaded_by,created_at) VALUES(?,?,?,?,?)",(jid,Path(uploaded.name).name,str(dest),uid,now()))
    audit(uid,"CARGAR_EVIDENCIA","JOB",jid,Path(uploaded.name).name)

def generate_supervision_key(jid,employee_id,minutes=60):
    raw="SGDI-"+"-".join("".join(secrets.choice(string.ascii_uppercase+string.digits) for _ in range(4)) for _ in range(3))
    with db() as conn:
        conn.execute("INSERT INTO supervision_keys(job_id,employee_id,key_hash,key_hint,expires_at,created_at) VALUES(?,?,?,?,?,?)",(jid,employee_id,hash_key(raw),raw[-4:],(datetime.now()+timedelta(minutes=minutes)).strftime("%Y-%m-%d %H:%M:%S"),now()))
        conn.execute("UPDATE jobs SET status='PENDIENTE_SUPERVISION',updated_at=? WHERE id=?",(now(),jid))
    return raw

def validate_key(raw):
    with db() as conn: row=conn.execute("SELECT k.*,j.*,u.full_name AS employee FROM supervision_keys k JOIN jobs j ON j.id=k.job_id JOIN users u ON u.id=k.employee_id WHERE k.key_hash=? AND k.used=0",(hash_key(raw.strip()),)).fetchone()
    if not row: return None,"Clave inválida o ya utilizada."
    if datetime.now()>datetime.strptime(row["expires_at"],"%Y-%m-%d %H:%M:%S"): return None,"La clave ha expirado."
    return row,""

def supervise(raw,supervisor_id,decision,comments):
    row,msg=validate_key(raw)
    if not row: raise ValueError(msg)
    if decision!="APROBAR" and not comments.strip(): raise ValueError("Debe indicar el motivo de la corrección o rechazo.")
    status="APROBADO" if decision=="APROBAR" else ("EN_PROCESO" if decision=="SOLICITAR_CORRECCIÓN" else "RECHAZADO")
    with db() as conn:
        conn.execute("UPDATE supervision_keys SET used=1,used_at=?,supervisor_name=(SELECT full_name FROM users WHERE id=?) WHERE id=?",(now(),supervisor_id,row["id"]))
        conn.execute("UPDATE jobs SET status=?,progress=? ,updated_at=? WHERE id=?",(status,100 if decision=="APROBAR" else row["progress"],now(),row["job_id"]))
        conn.execute("INSERT INTO supervision_history(job_id,key_id,supervisor_id,decision,comments,created_at) VALUES(?,?,?,?,?,?)",(row["job_id"],row["id"],supervisor_id,decision,comments.strip(),now()))
    audit(supervisor_id,"SUPERVISAR_TRABAJO","JOB",row["job_id"],f"Decisión={decision};{comments}")

def metrics():
    with db() as conn:
        q=lambda sql: conn.execute(sql).fetchone()["c"]
        return {"docs":q("SELECT COUNT(*) c FROM documents"),"unreviewed":q("SELECT COUNT(*) c FROM documents WHERE review_status='SIN_REVISAR'"),"vigent":q("SELECT COUNT(*) c FROM documents WHERE status='VIGENTE'"),"jobs":q("SELECT COUNT(*) c FROM jobs"),"pending_jobs":q("SELECT COUNT(*) c FROM jobs WHERE status IN ('PENDIENTE','EN_PROCESO','PENDIENTE_SUPERVISION')"),"users":q("SELECT COUNT(*) c FROM users WHERE active=1")}

def audit_rows(limit=300):
    with db() as conn: return conn.execute("SELECT a.*,COALESCE(u.full_name,'Sistema') AS user_name FROM audit_log a LEFT JOIN users u ON u.id=a.user_id ORDER BY a.created_at DESC LIMIT ?",(limit,)).fetchall()

def qr_bytes(text):
    if qrcode is None: return None
    img=qrcode.make(text); out=io.BytesIO(); img.save(out,format="PNG"); return out.getvalue()

def suggest_standard(title,filename,department,doc_type):
    text=(title+" "+filename).lower()
    suggestions=[]
    if any(x in text for x in ["procedimiento","proceso"]): suggestions.append("Usar código de Procedimiento y revisión formal.")
    if any(x in text for x in ["formato","registro","checklist"]): suggestions.append("Clasificar como formato/registro y conservar trazabilidad.")
    if any(x in text for x in ["calidad","iso","rnc","no conform"]): suggestions.append("Enviar a Control de Calidad para revisión.")
    if any(x in text for x in ["mantenimiento","equipo","maquina"]): suggestions.append("Clasificar en Mantenimiento y asociar a una orden si corresponde.")
    return suggestions or [f"Clasificación propuesta: {doc_type} · {department}.","Verificar responsable, versión, fecha y aprobación antes de ponerlo VIGENTE."]

def login_screen():
    st.markdown('<div class="main-title"><h1>🏭 SGD-I</h1><p>Sistema de Gestión Documental Industrial</p></div>',unsafe_allow_html=True)
    a,b,c=st.columns([1,2,1])
    with b:
        st.subheader("Acceso al sistema")
        with st.form("login"):
            username=st.text_input("Usuario")
            password=st.text_input("Contraseña",type="password")
            ok=st.form_submit_button("🔐 Iniciar sesión",use_container_width=True,type="primary")
        if ok:
            user=authenticate(username,password)
            if user:
                st.session_state.authenticated=True; st.session_state.user=dict(user); audit(user["id"],"LOGIN","USER",user["id"],"Inicio correcto"); st.rerun()
            st.error("Usuario o contraseña incorrectos.")

def dashboard(user):
    st.markdown('<div class="main-title"><h1>🏭 Panel de Gestión Industrial</h1><p>Control documental, trabajos, aprobaciones y trazabilidad</p></div>',unsafe_allow_html=True)
    m=metrics(); cols=st.columns(6)
    for col,label,key in zip(cols,["Documentos","Sin revisar","Vigentes","Trabajos","Trabajos pendientes","Usuarios activos"],["docs","unreviewed","vigent","jobs","pending_jobs","users"]): col.metric(label,m[key])
    st.subheader("🎯 Mi trabajo de hoy")
    jobs=get_jobs(user)
    if jobs:
        for j in jobs[:8]:
            with st.container(border=True):
                a,b,c=st.columns([3,3,1]); a.write(f"**{j['job_code']} — {j['title']}**"); a.caption(f"{j['employee']} · {j['department']} · {j['project_name'] or 'Sin proyecto'}"); b.progress(j["progress"]/100); b.caption(j["status"]+" · "+(j["due_date"] or "Sin fecha")); c.write(f"**{j['progress']}%**")
    else: st.info("No hay trabajos pendientes para mostrar.")
    recent,unreviewed,due=alerts()
    st.subheader("🔔 Resumen de alertas")
    x,y,z=st.columns(3); x.metric("Recientes",len(recent)); y.metric("Sin revisar",len(unreviewed)); z.metric("Por vencer/vencidos",len(due))

def documents_page(user):
    st.header("📄 Gestión documental")
    tabs=st.tabs(["📥 Entrada","📚 Registro","🔄 Nueva versión / movimiento","🧾 Historial y QR"])
    projects=get_projects(); project_map={p["name"]:p["id"] for p in projects}; project_names=["Sin proyecto"]+list(project_map)
    with tabs[0]:
        with st.form("upload_doc",clear_on_submit=True):
            title=st.text_input("Nombre / título")
            c1,c2=st.columns(2); dept=c1.selectbox("Departamento",DEPARTMENTS); dtype=c2.selectbox("Tipo",DOC_TYPES)
            project=c1.selectbox("Proyecto",project_names); due=c2.date_input("Fecha de revisión/vencimiento",value=None)
            file=st.file_uploader("Archivo",type=["pdf","png","jpg","jpeg","tif","tiff","doc","docx","xls","xlsx","csv","txt"])
            ok=st.form_submit_button("📥 Registrar documento",use_container_width=True,type="primary")
        if ok:
            try:
                code=create_document(file,title,dept,dtype,user["id"],project_map.get(project),due.isoformat() if due else None)
                st.success(f"Documento {code} registrado como SIN REVISAR.")
                st.info("Recomendaciones: "+" | ".join(suggest_standard(title,file.name if file else "",dept,dtype)))
            except Exception as e: st.error(str(e))
    with tabs[1]:
        c1,c2,c3=st.columns(3); sort=c1.selectbox("Ordenar por",["Nombre","Usuario","Más recientes","Estado","Versión"]); filt=c2.selectbox("Departamento",["Todos"]+DEPARTMENTS); review=c3.selectbox("Revisión",["Todos"]+REVIEW_STATES)
        docs=get_documents(sort,filt,review)
        for d in docs:
            with st.container(border=True):
                a,b=st.columns([5,2]); a.write(f"**{d['title']}** · `{d['code']}`"); a.caption(f"{d['filename']} · {d['department']} · {d['document_type']} · V{d['version']} · {d['status']} · {d['review_status']}"); a.caption(f"Usuario: {d['uploader']} · Proyecto: {d['project_name'] or 'Sin proyecto'} · Creado: {d['created_at']}")
                path=Path(d["stored_path"])
                if path.exists(): b.download_button("⬇️ Descargar",path.read_bytes(),file_name=d["filename"],key=f"dl{d['id']}",use_container_width=True)
                if user["role"] in ("ADMINISTRADOR","JEFE_PRODUCCION","CALIDAD","AUDITOR"):
                    if d["review_status"]=="SIN_REVISAR" and b.button("🔎 Marcar revisado",key=f"rv{d['id']}",use_container_width=True): mark_review(d["id"],user["id"]); st.rerun()
                    if d["status"]=="EN_REVISION":
                        if b.button("✅ Aprobar",key=f"ap{d['id']}",use_container_width=True): approve_document(d["id"],user["id"],True); st.rerun()
                        if b.button("⚠️ Observar",key=f"ob{d['id']}",use_container_width=True): approve_document(d["id"],user["id"],False,"Revisión requiere corrección"); st.rerun()
    with tabs[2]:
        docs=get_documents("Nombre"); names={f"{d['code']} · {d['title']}":d for d in docs}; choice=st.selectbox("Documento",list(names) or ["Sin documentos"])
        if names:
            d=names[choice]
            with st.form("newver"):
                f=st.file_uploader("Nueva versión",key="newverfile"); reason=st.text_input("Motivo del cambio"); ok=st.form_submit_button("Crear nueva versión",type="primary")
            if ok:
                try: add_document_version(d["id"],f,reason,user["id"]); st.success("Nueva versión creada y devuelta a SIN REVISAR."); st.rerun()
                except Exception as e: st.error(str(e))
            st.divider(); st.subheader("Transferir documento")
            with st.form("move_doc"):
                nd=st.selectbox("Nuevo departamento",DEPARTMENTS); np=st.selectbox("Nuevo proyecto",project_names); rs=st.text_input("Motivo obligatorio"); mv=st.form_submit_button("Transferir",type="primary")
            if mv:
                if not rs.strip(): st.error("El motivo es obligatorio.")
                else: move_document(d["id"],nd,project_map.get(np),rs,user["id"]); st.success("Documento transferido."); st.rerun()
    with tabs[3]:
        docs=get_documents("Más recientes"); names={f"{d['code']} · {d['title']}":d for d in docs}; choice=st.selectbox("Consultar documento",list(names) or ["Sin documentos"],key="histdoc")
        if names:
            d=names[choice]; versions,moves=document_history(d["id"]); st.write(f"### {d['code']} — {d['title']}")
            qr=qr_bytes(f"SGD-I|{d['code']}|{d['title']}|{d['status']}|V{d['version']}")
            if qr: st.image(qr,width=160); st.download_button("Descargar QR",qr,file_name=f"{d['code']}.png",mime="image/png")
            st.subheader("Versiones");
            for v in versions: st.write(f"V{v['version']} · {v['filename']} · {v['user_name']} · {v['created_at']} · {v['change_reason'] or ''}")
            st.subheader("Movimientos");
            for mv in moves: st.write(f"{mv['created_at']} · {mv['from_department']} → {mv['to_department']} · {mv['user_name']} · {mv['reason']}")

def jobs_page(user):
    st.header("🛠️ Trabajos y supervisión")
    tabs=st.tabs(["📋 Trabajos","🔑 Generar clave","🧑‍💼 Supervisar con clave"] if user["role"] in SUPERVISOR_ROLES or user["role"]=="ADMINISTRADOR" else ["📋 Mis trabajos","🔑 Generar clave"])
    jobs=get_jobs(user)
    with tabs[0]:
        if user["role"] in ("ADMINISTRADOR","JEFE_PRODUCCION"):
            with st.expander("➕ Crear trabajo"):
                us=get_users(True); active=[u for u in us if u["role"] not in ("ADMINISTRADOR",)]
                if active:
                    with st.form("createjob"):
                        title=st.text_input("Título"); desc=st.text_area("Descripción"); dept=st.selectbox("Departamento",DEPARTMENTS); proj=st.selectbox("Proyecto",["Sin proyecto"]+[p["name"] for p in get_projects()]); emp=st.selectbox("Empleado",[f"{u['full_name']} ({u['username']})" for u in active]); due=st.date_input("Fecha límite",value=None); ok=st.form_submit_button("Crear trabajo",type="primary")
                    if ok:
                        uid=next(u["id"] for u in active if f"{u['full_name']} ({u['username']})"==emp); pmap={p["name"]:p["id"] for p in get_projects()}; code=create_job(title,desc,dept,pmap.get(proj),uid,due.isoformat() if due else None); audit(user["id"],"CREAR_TRABAJO","JOB",code,title); st.success(f"Trabajo creado: {code}"); st.rerun()
        if not jobs: st.info("No hay trabajos.")
        for j in jobs:
            with st.container(border=True):
                st.write(f"**{j['job_code']} — {j['title']}**"); st.caption(f"{j['employee']} · {j['department']} · {j['project_name'] or 'Sin proyecto'} · {j['status']}")
                if user["id"]==j["assigned_to"] or user["role"] in ("ADMINISTRADOR","JEFE_PRODUCCION"):
                    with st.form(f"job{j['id']}"):
                        status=st.selectbox("Estado",JOB_STATUSES,index=JOB_STATUSES.index(j["status"])); progress=st.slider("Progreso",0,100,int(j["progress"])); ev=st.file_uploader("Evidencia",key=f"ev{j['id']}"); ok=st.form_submit_button("Guardar avance")
                    if ok:
                        update_job(j["id"],status,progress,user["id"])
                        if ev: save_job_evidence(j["id"],ev,user["id"])
                        st.success("Avance guardado."); st.rerun()
    with tabs[1]:
        eligible=[j for j in jobs if j["assigned_to"]==user["id"] or user["role"] in ("ADMINISTRADOR","JEFE_PRODUCCION")]
        if eligible:
            opts={f"{j['job_code']} · {j['title']}":j for j in eligible}; ch=st.selectbox("Trabajo",list(opts)); mins=st.selectbox("Validez",[15,30,60,120,240],index=2); 
            if st.button("🔑 Generar clave",type="primary"):
                raw=generate_supervision_key(opts[ch]["id"],opts[ch]["assigned_to"],mins); st.success("Clave generada. Entréguela al supervisor."); st.code(raw)
        else: st.info("No tienes trabajos disponibles para generar una clave.")
    if len(tabs)>2:
        with tabs[2]:
            raw=st.text_input("Clave de supervisión",placeholder="SGDI-XXXX-XXXX-XXXX");
            if raw:
                row,msg=validate_key(raw)
                if row: st.info(f"Trabajo: {row['job_code']} · {row['title']} · Empleado: {row['employee']} · Progreso: {row['progress']}%")
                else: st.error(msg)
            decision=st.selectbox("Decisión",["APROBAR","SOLICITAR_CORRECCIÓN","RECHAZAR"]); comments=st.text_area("Comentarios")
            if st.button("Registrar supervisión",type="primary"):
                try: supervise(raw,user["id"],decision,comments); st.success("Supervisión registrada."); st.rerun()
                except Exception as e: st.error(str(e))

def alerts_page(user):
    st.header("🔔 Buzón de alertas")
    recent,unreviewed,due=alerts(); c1,c2,c3=st.columns(3); c1.metric("Archivos recientes",len(recent)); c2.metric("Sin revisar",len(unreviewed)); c3.metric("Vencidos / próximos",len(due))
    for title,data,cls in [("🔴 Archivos sin revisar",unreviewed,"danger-card"),("🟡 Fechas próximas o vencidas",due,"alert-card"),("🆕 Archivos recientes",recent,"success-card")]:
        st.subheader(title)
        for d in data[:30]:
            st.markdown(f'<div class="{cls}"><b>{d["code"]} — {d["title"]}</b><br>{d["filename"]} · {d["uploader"]} · {d["department"]} · {d["created_at"]}'+(f'<br>Fecha: {d["due_date"]}' if d["due_date"] else '')+'</div>',unsafe_allow_html=True)
            if d["review_status"]=="SIN_REVISAR" and st.button("Marcar revisado",key=f"alertrev{d['id']}"): mark_review(d["id"],user["id"]); st.rerun()

def users_page(user):
    if user["role"] not in ("ADMINISTRADOR","JEFE_PRODUCCION"): st.error("Acceso no autorizado."); return
    st.header("👥 Usuarios")
    if user["role"]=="ADMINISTRADOR":
        with st.expander("➕ Crear usuario"):
            with st.form("newuser"):
                a,b=st.columns(2); username=a.text_input("Usuario"); full=a.text_input("Nombre completo"); pwd=b.text_input("Contraseña",type="password"); role=b.selectbox("Rol",ROLES); dept=a.selectbox("Departamento",DEPARTMENTS); ok=st.form_submit_button("Crear usuario",type="primary")
            if ok:
                try: create_user(username,full,pwd,role,dept); st.success("Usuario creado."); st.rerun()
                except Exception as e: st.error(str(e))
    sort=st.selectbox("Ordenar usuarios por",["Nombre","Usuario","Rol","Departamento"])
    users=get_users(); keymap={"Nombre":"full_name","Usuario":"username","Rol":"role","Departamento":"department"}; users=sorted(users,key=lambda x:(x[keymap[sort]].lower(),x["username"].lower()))
    for u in users:
        with st.container(border=True):
            a,b=st.columns([5,2]); a.write(f"**{u['full_name']}** · `{u['username']}`"); a.caption(f"{u['role']} · {u['department']} · {'ACTIVO' if u['active'] else 'INACTIVO'}")
            if user["role"]=="ADMINISTRADOR" and u["username"]!="Mariana":
                label="Desactivar" if u["active"] else "Activar"
                if b.button(label,key=f"act{u['id']}"): set_user_active(u["id"],not bool(u["active"]),user["id"]); st.rerun()

def projects_page(user):
    st.header("📁 Proyectos")
    if user["role"]=="ADMINISTRADOR":
        with st.form("project"):
            a,b=st.columns(2); name=a.text_input("Nombre"); dept=a.selectbox("Departamento",DEPARTMENTS); desc=b.text_area("Descripción"); mgr=b.selectbox("Responsable",[f"{u['full_name']} ({u['id']})" for u in get_users(True)]); ok=st.form_submit_button("Crear proyecto",type="primary")
        if ok:
            mid=int(mgr.rsplit("(",1)[1].rstrip(")")); st.success(f"Proyecto creado: {create_project(name,desc,dept,mid)}"); st.rerun()
    for p in get_projects():
        st.markdown(f'<div class="card"><b>{p["code"]} — {p["name"]}</b><br>{p["department"] or "General"} · Responsable: {p["manager"] or "Sin asignar"}<br>{p["description"] or "Sin descripción"}</div>',unsafe_allow_html=True)

def audit_page(user):
    if user["role"] not in ("ADMINISTRADOR","JEFE_PRODUCCION"): st.error("Acceso no autorizado."); return
    st.header("🔎 Auditoría")
    rows=audit_rows(); sort=st.selectbox("Ordenar",["Más recientes","Usuario","Acción","Entidad"])
    if sort=="Usuario": rows=sorted(rows,key=lambda x:(x["user_name"].lower(),x["created_at"]),reverse=False)
    elif sort=="Acción": rows=sorted(rows,key=lambda x:(x["action"].lower(),x["created_at"]),reverse=False)
    elif sort=="Entidad": rows=sorted(rows,key=lambda x:(x["entity"].lower(),x["created_at"]),reverse=False)
    for r in rows: st.write(f"`{r['created_at']}` · **{r['user_name']}** · `{r['action']}` · `{r['entity']}` `{r['entity_id']}` · {r['details'] or ''}")

def templates_page(user):
    st.header("📝 Generador de formatos")
    kind=st.selectbox("Tipo de plantilla",["Procedimiento","Instructivo","Formato","Checklist","Informe","Acción correctiva","Orden de producción","Mantenimiento"])
    title=st.text_input("Título",value=kind)
    if st.button("Generar estructura",type="primary"):
        templates={
        "Procedimiento":"1. Objetivo\n2. Alcance\n3. Responsabilidades\n4. Definiciones\n5. Desarrollo del procedimiento\n6. Indicadores\n7. Registros\n8. Control de cambios",
        "Instructivo":"1. Objetivo\n2. Materiales/equipos\n3. Seguridad\n4. Pasos de trabajo\n5. Criterios de aceptación\n6. Registro",
        "Formato":"Código: ______\nVersión: ______\nFecha: ______\nResponsable: ______\nDatos: ______________________________\nObservaciones: ______________________\nFirma: ______",
        "Checklist":"Área: ______\nFecha: ______\nResponsable: ______\n\n☐ Cumple\n☐ No cumple\n☐ No aplica\nObservaciones: ______________________",
        "Informe":"1. Resumen ejecutivo\n2. Objetivo\n3. Datos recopilados\n4. Resultados\n5. Hallazgos\n6. Acciones\n7. Conclusión",
        "Acción correctiva":"No conformidad: ______\nCausa raíz: ______\nAcción inmediata: ______\nAcción correctiva: ______\nResponsable: ______\nFecha compromiso: ______\nVerificación de eficacia: ______",
        "Orden de producción":"Producto: ______\nCliente: ______\nCantidad: ______\nMateria prima: ______\nProceso: ______\nResponsable: ______\nFecha: ______\nCriterios de calidad: ______",
        "Mantenimiento":"Equipo: ______\nCódigo: ______\nTipo: Preventivo/Correctivo\nFalla/actividad: ______\nRepuestos: ______\nTécnico: ______\nFecha: ______\nResultado: ______"}[kind]
        st.text_area("Estructura lista para copiar",templates,height=300)

def main():
    init_db()
    if not st.session_state.get("authenticated"): login_screen(); return
    user=st.session_state["user"]
    st.sidebar.title("🏭 SGD-I"); st.sidebar.caption(f"{user['full_name']} · {user['role']}"); st.sidebar.caption(user["department"])
    if user["role"]=="ADMINISTRADOR":
        _,unrev,due=alerts(); st.sidebar.warning(f"🔔 {len(unrev)} sin revisar")
        if due: st.sidebar.error(f"⚠️ {len(due)} por vencer/vencidos")
    if st.sidebar.button("Cerrar sesión",use_container_width=True): audit(user["id"],"LOGOUT","USER",user["id"],""); st.session_state.clear(); st.rerun()
    pages=["📊 Dashboard","📄 Documentos","🛠️ Trabajos","📝 Plantillas","📁 Proyectos"]
    if user["role"]=="ADMINISTRADOR": pages += ["🔔 Buzón de alertas","👥 Usuarios","🔎 Auditoría"]
    elif user["role"]=="JEFE_PRODUCCION": pages += ["👥 Usuarios","🔎 Auditoría"]
    page=st.sidebar.radio("Módulos",pages)
    if page=="📊 Dashboard": dashboard(user)
    elif page=="📄 Documentos": documents_page(user)
    elif page=="🛠️ Trabajos": jobs_page(user)
    elif page=="📝 Plantillas": templates_page(user)
    elif page=="📁 Proyectos": projects_page(user)
    elif page=="🔔 Buzón de alertas": alerts_page(user) if user["role"]=="ADMINISTRADOR" else st.error("Acceso no autorizado.")
    elif page=="👥 Usuarios": users_page(user)
    elif page=="🔎 Auditoría": audit_page(user)

if __name__=="__main__": main()
