const express=require('express'),session=require('express-session'),bcrypt=require('bcryptjs'),Database=require('better-sqlite3'),crypto=require('crypto'),path=require('path');
const db=new Database(process.env.DB_PATH||path.join(__dirname,'police.db'));db.pragma('journal_mode=WAL');db.pragma('foreign_keys=ON');
db.exec(`CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY,username TEXT UNIQUE NOT NULL,hash TEXT NOT NULL,name TEXT NOT NULL,role TEXT NOT NULL CHECK(role IN('officer','staff','admin')),can_add INTEGER DEFAULT 0);
CREATE TABLE IF NOT EXISTS players(id INTEGER PRIMARY KEY,full_name TEXT NOT NULL,national_id TEXT UNIQUE NOT NULL,roblox TEXT NOT NULL,avatar TEXT DEFAULT '',age INTEGER DEFAULT 0,phone TEXT DEFAULT '',address TEXT DEFAULT '',job TEXT DEFAULT '');
CREATE TABLE IF NOT EXISTS records(id INTEGER PRIMARY KEY,player_id INTEGER NOT NULL REFERENCES players(id) ON DELETE CASCADE,type TEXT NOT NULL CHECK(type IN('criminal','arrest','fine','note')),title TEXT NOT NULL,details TEXT DEFAULT '',amount INTEGER DEFAULT 0,officer TEXT NOT NULL,at TEXT DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS permits(id INTEGER PRIMARY KEY,player_id INTEGER NOT NULL REFERENCES players(id) ON DELETE CASCADE,kind TEXT NOT NULL CHECK(kind IN('driving','weapon','business','special')),status TEXT NOT NULL CHECK(status IN('approved','suspended','expired')),expires TEXT,officer TEXT NOT NULL,UNIQUE(player_id,kind));
CREATE TABLE IF NOT EXISTS activity(id INTEGER PRIMARY KEY,text TEXT NOT NULL,officer TEXT NOT NULL,at TEXT DEFAULT CURRENT_TIMESTAMP);`);
{const t=db.prepare("SELECT sql FROM sqlite_master WHERE name='users'").get()?.sql||'';
if(!t.includes("'staff'")){db.pragma('foreign_keys=OFF');db.exec("ALTER TABLE users RENAME TO users_old;CREATE TABLE users(id INTEGER PRIMARY KEY,username TEXT UNIQUE NOT NULL,hash TEXT NOT NULL,name TEXT NOT NULL,role TEXT NOT NULL CHECK(role IN('officer','staff','admin')),can_add INTEGER DEFAULT 0);INSERT INTO users(id,username,hash,name,role) SELECT id,username,hash,name,role FROM users_old;DROP TABLE users_old;");db.pragma('foreign_keys=ON')}}
for(const c of['discord_id','roblox_id']){try{db.exec(`ALTER TABLE users ADD COLUMN ${c} TEXT`)}catch{}db.exec(`CREATE UNIQUE INDEX IF NOT EXISTS u_${c} ON users(${c})`)}
if(!db.prepare('SELECT 1 FROM users').get()){const pw=process.env.ADMIN_PASSWORD||crypto.randomBytes(9).toString('base64url');
db.prepare('INSERT INTO users(username,hash,name,role) VALUES(?,?,?,?)').run('admin',bcrypt.hashSync(pw,12),'מנהל מערכת','admin');
console.log(`\n== נוצר משתמש ראשוני ==\nמשתמש: admin\nסיסמה: ${pw}\n`);}
class E extends Error{}
const S=(v,max,req=true)=>{v=typeof v==='string'?v.trim():'';if(req&&!v)throw new E('חסר שדה חובה');if(v.length>max)throw new E('ערך ארוך מדי');return v};
const rx=(v,r,m)=>{if(!r.test(v))throw new E(m);return v};
const P=b=>({full_name:rx(S(b.roblox,20),/^\w{3,20}$/,'שם משתמש רובלוקס לא תקין'),national_id:S(b.roblox,20),roblox:rx(S(b.roblox,20),/^\w{3,20}$/,'שם משתמש רובלוקס לא תקין'),
avatar:(v=>v&&!/^https:\/\/[^\s"'<>]+$/.test(v)?(()=>{throw new E('כתובת תמונה חייבת להתחיל ב-https')})():v)(S(b.avatar,300,false)),
age:Math.min(120,Math.max(0,parseInt(b.age)||0)),job:S(b.job,50,false)});
const log=(u,t)=>db.prepare('INSERT INTO activity(text,officer) VALUES(?,?)').run(t,u.name);
const wrap=f=>(q,s)=>{try{const r=f(q,s);if(r!==undefined)s.json(r)}catch(e){if(e instanceof E)return s.status(400).json({error:e.message});
if(/UNIQUE/.test(e.message))return s.status(400).json({error:'הערך כבר קיים (שחקן עם אותו שם רובלוקס קיים)'});console.error(e);s.status(500).json({error:'שגיאת שרת'})}};
const auth=(q,s,n)=>{if(q.session.u?.guest)return n();const x=q.session.u&&db.prepare('SELECT id,name,role,can_add FROM users WHERE id=?').get(q.session.u.id);if(!x)return s.status(401).json({error:'נדרשת התחברות'});q.session.u={id:x.id,name:x.name,role:x.role,can_add:x.role==='admin'||!!x.can_add};n()};
const needCode=(q,s,n)=>{const a=Buffer.from(String(q.get('x-action-code')||'')),b=Buffer.from(process.env.ACTION_CODE||'ad');a.length===b.length&&crypto.timingSafeEqual(a,b)?n():s.status(403).json({error:'קוד אישור שגוי'})};
const stf=(q,s,n)=>q.session.u.role!=='officer'?n():s.status(403).json({error:'אין הרשאה'});
const adm=(q,s,n)=>q.session.u.role==='admin'?n():s.status(403).json({error:'אין הרשאה'});
const app=express();app.set('trust proxy',1);app.disable('x-powered-by');app.use(express.json({limit:'20kb'}));
app.use((q,s,n)=>{s.set({'X-Content-Type-Options':'nosniff','X-Frame-Options':'DENY','Content-Security-Policy':"default-src 'self';img-src 'self' https: data:;style-src 'self' 'unsafe-inline';script-src 'self'"});
if(q.method!=='GET'&&!q.is('json'))return s.status(415).json({error:'סוג בקשה לא נתמך'});n()});
app.use(session({name:'sid',secret:process.env.SESSION_SECRET||crypto.randomBytes(32).toString('hex'),resave:false,saveUninitialized:false,
cookie:{httpOnly:true,sameSite:'strict',secure:process.env.NODE_ENV==='production',maxAge:8*3600e3}}));
const PUB=require('fs').existsSync(path.join(__dirname,'public','index.html'))?path.join(__dirname,'public'):__dirname;
app.get('/',(q,s)=>s.sendFile(path.join(PUB,'index.html')));app.get('/app.js',(q,s)=>s.sendFile(path.join(PUB,'app.js')));
const tries=new Map(),dummy=bcrypt.hashSync('x',12);
app.post('/api/login',wrap((q,s)=>{const k=q.ip,t=tries.get(k)||{n:0,t:Date.now()};if(Date.now()-t.t>9e5){t.n=0;t.t=Date.now()}
if(t.n>=8)throw new E('יותר מדי ניסיונות. נסה שוב בעוד כמה דקות');if(q.body.code!==undefined){const a=Buffer.from(String(q.body.code)),c=Buffer.from(process.env.LOGIN_CODE||'KRdix');
if(!(a.length===c.length&&crypto.timingSafeEqual(a,c))){t.n++;tries.set(k,t);throw new E('קוד שגוי')}tries.delete(k);const nm=S(q.body.name,30,false)||'שוטר';
return new Promise(r=>q.session.regenerate(()=>{q.session.u={id:0,name:nm,role:'officer',can_add:false,guest:1};s.json(q.session.u);r()}))&&undefined}
const u=db.prepare('SELECT * FROM users WHERE username=?').get(S(q.body.username,30));
const ok=bcrypt.compareSync(String(q.body.password||'').slice(0,100),u?u.hash:dummy);if(!u||!ok){t.n++;tries.set(k,t);throw new E('שם משתמש או סיסמה שגויים')}
tries.delete(k);return new Promise(r=>q.session.regenerate(()=>{q.session.u={id:u.id,name:u.name,role:u.role,can_add:u.role==='admin'||!!u.can_add};s.json(q.session.u);r()}))&&undefined}));
app.post('/api/logout',(q,s)=>q.session.destroy(()=>s.json({ok:1})));
app.get('/api/me',auth,(q,s)=>s.json(q.session.u));
app.get('/api/roblox/:name',auth,async(q,s)=>{try{const n=q.params.name;if(!/^\w{3,20}$/.test(n))return s.status(400).json({error:'שם משתמש לא תקין'});
const r=await fetch('https://users.roblox.com/v1/usernames/users',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({usernames:[n],excludeBannedUsers:false})});
const u=(await r.json()).data?.[0];if(!u)return s.status(404).json({error:'המשתמש לא נמצא ברובלוקס'});
const t=await fetch(`https://thumbnails.roblox.com/v1/users/avatar-headshot?userIds=${u.id}&size=150x150&format=Png`);
s.json({id:u.id,name:u.name,displayName:u.displayName,avatar:(await t.json()).data?.[0]?.imageUrl||''})}catch{s.status(502).json({error:'לא ניתן להתחבר לרובלוקס כרגע'})}});
const today=()=>new Date().toISOString().slice(0,10);
app.get('/api/stats',auth,wrap(()=>{const d=today(),c=x=>db.prepare(x).get(d).c;return{
players:c('SELECT COUNT(*) c FROM players WHERE ?'),active:c("SELECT COUNT(*) c FROM permits WHERE status='approved' AND (expires IS NULL OR expires>=?)"),
suspended:c("SELECT COUNT(*) c FROM permits WHERE status='suspended' AND ?"),
criminal:c("SELECT COUNT(DISTINCT player_id) c FROM records WHERE type IN('criminal','arrest') AND ?"),
activity:db.prepare('SELECT * FROM activity ORDER BY id DESC LIMIT 12').all()}}));
app.get('/api/players',auth,wrap(q=>{const l='%'+S(q.query.q||'',40,false).replace(/[%_]/g,'')+'%';
return db.prepare('SELECT id,full_name,national_id,roblox,avatar,job FROM players WHERE full_name LIKE ? OR national_id LIKE ? OR roblox LIKE ? ORDER BY id DESC LIMIT 100').all(l,l,l)}));
app.get('/api/players/:id',auth,wrap((q,s)=>{const p=db.prepare('SELECT * FROM players WHERE id=?').get(q.params.id);if(!p)return s.status(404).json({error:'לא נמצא'});
const d=today(),permits=db.prepare('SELECT * FROM permits WHERE player_id=?').all(p.id).map(x=>({...x,status:x.status==='approved'&&x.expires&&x.expires<d?'expired':x.status}));
return{p,permits,records:db.prepare('SELECT * FROM records WHERE player_id=? ORDER BY id DESC').all(p.id)}}));
app.post('/api/players',auth,wrap((q,s)=>{if(!q.session.u.can_add)throw new E('אין הרשאה לפתוח תיק חדש');const p=P(q.body);const r=db.prepare('INSERT INTO players(full_name,national_id,roblox,avatar,age,job) VALUES(@full_name,@national_id,@roblox,@avatar,@age,@job)').run(p);
log(q.session.u,`נפתח תיק חדש: ${p.full_name}`);return{id:Number(r.lastInsertRowid)}}));
app.put('/api/players/:id',auth,wrap(q=>{const p=P(q.body);db.prepare('UPDATE players SET full_name=@full_name,national_id=@national_id,roblox=@roblox,avatar=@avatar,age=@age,job=@job WHERE id=@id').run({...p,id:q.params.id});
log(q.session.u,`עודכנו פרטי ${p.full_name}`);return{ok:1}}));
app.post('/api/players/:id/records',auth,wrap((q,s)=>{const b=q.body,p=db.prepare('SELECT full_name FROM players WHERE id=?').get(q.params.id);if(!p)return s.status(404).json({error:'לא נמצא'});
if(!['criminal','arrest','fine','note'].includes(b.type))throw new E('סוג לא תקין');const t=S(b.title,100),amt=b.type==='fine'?Math.min(1e9,Math.max(0,parseInt(b.amount)||0)):0;
db.prepare('INSERT INTO records(player_id,type,title,details,amount,officer) VALUES(?,?,?,?,?,?)').run(q.params.id,b.type,t,S(b.details,1000,false),amt,q.session.u.name);
log(q.session.u,`נוסף רישום (${b.type}) ל-${p.full_name}: ${t}`);return{ok:1}}));
app.delete('/api/records/:id',auth,adm,needCode,wrap(q=>{db.prepare('DELETE FROM records WHERE id=?').run(q.params.id);log(q.session.u,'נמחק רישום');return{ok:1}}));
app.post('/api/players/:id/permits',auth,wrap((q,s)=>{const b=q.body,p=db.prepare('SELECT full_name FROM players WHERE id=?').get(q.params.id);if(!p)return s.status(404).json({error:'לא נמצא'});
if(!['driving','weapon','business','special'].includes(b.kind)||!['approved','suspended','expired'].includes(b.status))throw new E('נתונים לא תקינים');
const ex=S(b.expires,10,false);if(ex)rx(ex,/^\d{4}-\d{2}-\d{2}$/,'תאריך לא תקין');
db.prepare('INSERT INTO permits(player_id,kind,status,expires,officer) VALUES(?,?,?,?,?) ON CONFLICT(player_id,kind) DO UPDATE SET status=excluded.status,expires=excluded.expires,officer=excluded.officer').run(q.params.id,b.kind,b.status,ex||null,q.session.u.name);
log(q.session.u,`היתר ${b.kind} של ${p.full_name} עודכן ל-${b.status}`);return{ok:1}}));
app.delete('/api/players/:id',auth,adm,needCode,wrap(q=>{const p=db.prepare('SELECT full_name FROM players WHERE id=?').get(q.params.id);db.prepare('DELETE FROM players WHERE id=?').run(q.params.id);if(p)log(q.session.u,`נמחק תיק: ${p.full_name}`);return{ok:1}}));
app.delete('/api/activity/:id',auth,adm,needCode,wrap(q=>{db.prepare('DELETE FROM activity WHERE id=?').run(q.params.id);return{ok:1}}));
app.delete('/api/activity',auth,adm,needCode,wrap(()=>{db.prepare('DELETE FROM activity').run();return{ok:1}}));
app.put('/api/users/:id',auth,adm,needCode,wrap(q=>{const b=q.body;if(!['officer','staff','admin'].includes(b.role))throw new E('תפקיד לא תקין');if(+q.params.id===q.session.u.id&&b.role!=='admin')throw new E('לא ניתן להוריד לעצמך הרשאה');db.prepare('UPDATE users SET role=?,can_add=? WHERE id=?').run(b.role,b.can_add?1:0,q.params.id);return{ok:1}}));
app.get('/api/users',auth,adm,wrap(()=>db.prepare('SELECT id,username,name,role,can_add FROM users').all()));
app.post('/api/users',auth,adm,needCode,wrap(q=>{const b=q.body,pw=S(b.password,100);if(pw.length<8)throw new E('סיסמה חייבת להכיל לפחות 8 תווים');
if(!['officer','staff','admin'].includes(b.role))throw new E('תפקיד לא תקין');db.prepare('INSERT INTO users(username,hash,name,role,can_add) VALUES(?,?,?,?,?)').run(rx(S(b.username,30),/^\w{3,30}$/,'שם משתמש לא תקין'),bcrypt.hashSync(pw,12),S(b.name,40),b.role,b.can_add?1:0);return{ok:1}}));
app.delete('/api/users/:id',auth,adm,needCode,wrap((q,s)=>{if(+q.params.id===q.session.u.id)throw new E('לא ניתן למחוק את עצמך');db.prepare('DELETE FROM users WHERE id=?').run(q.params.id);return{ok:1}}));
const OA={discord:{auth:'https://discord.com/oauth2/authorize',tok:'https://discord.com/api/oauth2/token',me:'https://discord.com/api/users/@me',scope:'identify',id:u=>u.id,col:'discord_id'},
roblox:{auth:'https://apis.roblox.com/oauth/v1/authorize',tok:'https://apis.roblox.com/oauth/v1/token',me:'https://apis.roblox.com/oauth/v1/userinfo',scope:'openid profile',id:u=>u.sub,col:'roblox_id'}};
const cfg=p=>({id:process.env[p.toUpperCase()+'_CLIENT_ID'],secret:process.env[p.toUpperCase()+'_CLIENT_SECRET']});
const base=q=>process.env.BASE_URL||`${q.protocol}://${q.get('host')}`;
app.get('/api/providers',(q,s)=>s.json(Object.keys(OA).filter(p=>cfg(p).id)));
app.get('/auth/callback',async(q,s)=>{const o=q.session.oa;delete q.session.oa;try{
if(!o||o.st!==q.query.state||!q.query.code)throw 0;const p=OA[o.p],c=cfg(o.p);
const t=await(await fetch(p.tok,{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:new URLSearchParams({grant_type:'authorization_code',code:String(q.query.code),redirect_uri:base(q)+'/auth/callback',client_id:c.id,client_secret:c.secret})})).json();
const me=await(await fetch(p.me,{headers:{Authorization:'Bearer '+t.access_token}})).json();const id=String(p.id(me)||'');if(!id||id==='undefined')throw 0;
if(o.link&&q.session.u){db.prepare(`UPDATE users SET ${p.col}=? WHERE id=?`).run(id,q.session.u.id);return s.redirect('/')}
const u=db.prepare(`SELECT * FROM users WHERE ${p.col}=?`).get(id);if(!u)return s.redirect('/?err=nolink');
q.session.regenerate(()=>{q.session.u={id:u.id,name:u.name,role:u.role,can_add:u.role==='admin'||!!u.can_add};s.redirect('/')})}catch{s.redirect('/?err=1')}});
app.get('/auth/:p',(q,s)=>{const p=OA[q.params.p],c=cfg(q.params.p);if(!p||!c.id)return s.redirect('/?err=1');
const st=crypto.randomBytes(16).toString('hex');q.session.oa={st,p:q.params.p,link:!!q.query.link&&!!q.session.u};
s.redirect(p.auth+'?'+new URLSearchParams({client_id:c.id,redirect_uri:base(q)+'/auth/callback',response_type:'code',scope:p.scope,state:st}))});
app.listen(process.env.PORT||3000,()=>console.log('http://localhost:'+(process.env.PORT||3000)));
