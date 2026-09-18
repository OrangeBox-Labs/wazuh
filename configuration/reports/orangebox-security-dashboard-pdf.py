#!/usr/bin/env python3
"""OrangeBox Wazuh Security Dashboard PDF — visual SOC dashboard."""
import argparse,os,re,smtplib,urllib.request
from datetime import datetime
from email.mime.application import MIMEApplication
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from importlib.util import module_from_spec,spec_from_file_location
from pathlib import Path
from collections import Counter
try:
 from reportlab.pdfgen import canvas
 from reportlab.lib import colors
 from reportlab.lib.pagesizes import A4,landscape
 from reportlab.lib.utils import ImageReader
except ImportError as exc:
 raise SystemExit("Falta reportlab. Instálalo en el entorno que ejecutará este reporte (por ejemplo, python3-reportlab).") from exc

BASE_DIR=Path(__file__).resolve().parent
REPORT_PATH=BASE_DIR/"orangebox-security-report.py"
DEFAULT_FROM="wazuh@orangebox.cl"; SMTP_HOST="localhost"; SMTP_PORT=25
LOGO_URL="https://www.orangebox.cl/obox/img/logo-dark.png"
NAVY=colors.HexColor("#162831"); NAVY2=colors.HexColor("#213b46")
ORANGE=colors.HexColor("#f58220"); ORANGE2=colors.HexColor("#ff9b3d")
RED=colors.HexColor("#d44736"); CYAN=colors.HexColor("#2bb7b0")
BLUE=colors.HexColor("#4f86c6"); PURPLE=colors.HexColor("#8067b7")
TEXT=colors.HexColor("#263238"); MUTED=colors.HexColor("#6b7f87")
GRID=colors.HexColor("#dbe3e6"); WHITE=colors.white
CAT={"authentication":"AUTENTICACIÓN","web":"WEB","fim":"INTEGRIDAD","malware":"MALWARE / WEBSHELL","privilege":"PRIVILEGIOS","attack":"ATAQUES"}
CC={"authentication":ORANGE,"web":BLUE,"fim":CYAN,"malware":RED,"privilege":PURPLE,"attack":ORANGE2}

def report_module():
 s=spec_from_file_location("orangebox_security_report",REPORT_PATH)
 if s is None or s.loader is None: raise SystemExit(f"No se pudo cargar {REPORT_PATH}")
 m=module_from_spec(s); s.loader.exec_module(m); return m
def n(v): return f"{int(v):,}".replace(",",".")
def logo():
 p=Path("/tmp/orangebox-dashboard-logo.png")
 try:
  if not p.exists(): urllib.request.urlretrieve(LOGO_URL,p)
  return p
 except Exception: return None
def txt(c,v,x,y,size=8,col=TEXT,font="Helvetica",align="left"):
 c.setFont(font,size); c.setFillColor(col)
 {"left":c.drawString,"right":c.drawRightString,"center":c.drawCentredString}[align](x,y,str(v))
def box(c,x,y,w,h,fill=WHITE,stroke=GRID,r=8,lw=.7):
 c.setFillColor(fill); c.setStrokeColor(stroke); c.setLineWidth(lw); c.roundRect(x,y,w,h,r,fill=1,stroke=1)
def header(c,label,group,period,page,W,H):
 c.setFillColor(NAVY); c.rect(0,H-61,W,61,fill=1,stroke=0)
 c.setFillColor(ORANGE); c.rect(0,H-64,W,3,fill=1,stroke=0)
 p=logo()
 if p:
  try: c.drawImage(ImageReader(str(p)),25,H-49,width=116,height=32,preserveAspectRatio=True,mask="auto",anchor="sw")
  except Exception: txt(c,"Orange",25,H-42,18,ORANGE,"Helvetica-Bold")
 else:
  txt(c,"Orange",25,H-42,18,ORANGE,"Helvetica-Bold"); txt(c,"Box",83,H-42,18,WHITE,"Helvetica-Bold")
 txt(c,"SECURITY DASHBOARD",W/2,H-29,23,WHITE,"Helvetica-Bold","center")
 txt(c,f"WAZUH  ·  {label.upper()}  ·  {group}",W/2,H-46,8,colors.HexColor("#c5d2d7"),align="center")
 txt(c,f"{period}  |  PÁGINA {page}",W-25,H-43,7,colors.HexColor("#c5d2d7"),align="right")
def footer(c,W):
 c.setFillColor(NAVY); c.rect(0,0,W,18,fill=1,stroke=0); c.setFillColor(ORANGE); c.rect(0,18,W,2,fill=1,stroke=0)
 txt(c,"ORANGEBOX IT SERVICES  ·  WAZUH SECURITY OPERATIONS",25,6,6.5,colors.HexColor("#c5d2d7"))
 txt(c,"Fuente: Wazuh",W-25,6,6.5,colors.HexColor("#c5d2d7"),align="right")
def title(c,s,x,y,w,accent=ORANGE,sub=None):
 txt(c,s,x+12,y,11,TEXT,"Helvetica-Bold"); c.setFillColor(accent); c.roundRect(x,y-7,w,3,1.5,fill=1,stroke=0)
 if sub: txt(c,sub,x+w,y,7,MUTED,align="right")
def kpi(c,x,y,w,h,val,label,note,accent):
 box(c,x,y,w,h,NAVY2,NAVY2,7,0); c.setFillColor(accent); c.roundRect(x,y,w,4,2,fill=1,stroke=0)
 txt(c,n(val),x+12,y+h-29,24,accent,"Helvetica-Bold"); txt(c,label.upper(),x+12,y+h-44,7.5,WHITE,"Helvetica-Bold"); txt(c,note,x+12,y+10,6.5,colors.HexColor("#c6d4d9"))
def bars(c,rows,x,y,w,h,accent,max_items=6,labelw=145):
 rows=rows[:max_items]
 if not rows:
  txt(c,"SIN DATOS",x+w/2,y+h/2,8.5,MUTED,"Helvetica-Bold","center"); return
 mv=max(float(v) for _,v in rows) or 1
 rh=h/len(rows)
 labelw=min(labelw,w*.48)
 for i,(lab,val) in enumerate(rows):
  yy=y+h-(i+1)*rh+rh*.2
  txt(c,short_label(lab,30),x,yy+rh*.32,6.8,TEXT,"Helvetica-Bold")
  bx=x+labelw; bw=w-labelw-42
  c.setFillColor(colors.HexColor("#e9eef0")); c.roundRect(bx,yy,bw,9,4.5,fill=1,stroke=0)
  c.setFillColor(accent); c.roundRect(bx,yy,max(5,bw*float(val)/mv),9,4.5,fill=1,stroke=0)
  txt(c,n(val),x+w,yy+rh*.32,6.8,TEXT,"Helvetica-Bold","right")

def short_label(value,limit=30):
 value=str(value or "")
 return value if len(value)<=limit else value[:limit-1]+"…"

def catbars(def catbars(c,cats,x,y,w,h):
 rows=[(CAT[k],cats.get(k,{}).get("count",0),k) for k in CAT]; rows=[r for r in rows if r[1]]
 if not rows: txt(c,"SIN ACTIVIDAD",x+w/2,y+h/2,9,MUTED,"Helvetica-Bold","center"); return
 mv=max(v for _,v,_ in rows) or 1; rh=h/len(rows)
 for i,(lab,val,key) in enumerate(rows):
  yy=y+h-(i+1)*rh+rh*.2; txt(c,lab,x,yy+8,7.5,TEXT,"Helvetica-Bold"); bx=x+105; bw=w-150
  c.setFillColor(colors.HexColor("#e9eef0")); c.roundRect(bx,yy,bw,11,5.5,fill=1,stroke=0); c.setFillColor(CC[key]); c.roundRect(bx,yy,max(6,bw*val/mv),11,5.5,fill=1,stroke=0); txt(c,n(val),x+w,yy+8,7.5,TEXT,"Helvetica-Bold","right")
def line(c,timeline,x,y,w,h):
 ds=sorted(timeline)
 if not ds: txt(c,"SIN EVOLUCIÓN TEMPORAL",x+w/2,y+h/2,9,MUTED,"Helvetica-Bold","center"); return
 vs=[timeline[d] for d in ds]; mv=max(vs) or 1; L=x+36; B=y+20; CW=w-48; CH=h-35
 c.setStrokeColor(GRID); c.setLineWidth(.5)
 for j in range(5):
  gy=B+CH*j/4; c.line(L,gy,L+CW,gy); txt(c,n(mv*j/4),L-6,gy-2,5.5,MUTED,align="right")
 pts=[]
 for i,v in enumerate(vs): pts.append((L if len(vs)==1 else L+CW*i/(len(vs)-1),B+CH*v/mv))
 p=c.beginPath(); p.moveTo(*pts[0])
 for q in pts[1:]: p.lineTo(*q)
 c.setStrokeColor(ORANGE); c.setLineWidth(2.2); c.drawPath(p,stroke=1,fill=0)
 for px,py in pts: c.setFillColor(ORANGE); c.circle(px,py,2.4,fill=1,stroke=0)
 step=max(1,len(ds)//9)
 for i,d in enumerate(ds):
  if i%step==0 or i==len(ds)-1:
   px=L if len(ds)==1 else L+CW*i/(len(ds)-1); txt(c,d.strftime("%d/%m"),px,B-12,5.5,MUTED,align="center")
def donut(c,vals,labs,x,y,r,cols,total_label="TOTAL"):
 total=sum(vals) or 1; start=90
 for v,col in zip(vals,cols):
  sw=360*v/total; c.setFillColor(col); c.wedge(x-r,y-r,x+r,y+r,start-sw,start,fill=1,stroke=0); start-=sw
 c.setFillColor(WHITE); c.circle(x,y,r*.56,fill=1,stroke=0); txt(c,n(sum(vals)),x,y+2,16,TEXT,"Helvetica-Bold","center"); txt(c,total_label,x,y-11,6.5,MUTED,"Helvetica-Bold","center")
 ly=y+r-4
 for lab,v,col in zip(labs,vals,cols):
  c.setFillColor(col); c.rect(x+r+18,ly,7,7,fill=1,stroke=0); txt(c,lab,x+r+31,ly+1,6.2,TEXT); txt(c,n(v),x+r+118,ly+1,6.2,TEXT,"Helvetica-Bold","right"); ly-=14
def gauge(c,value,total,x,y,r):
 pct=max(0,min(1,float(value)/total if total else 0)); c.setLineWidth(13); c.setLineCap(1); c.setStrokeColor(colors.HexColor("#e8edef")); c.arc(x-r,y-r,x+r,y+r,0,180)
 col=CYAN if pct<.35 else ORANGE if pct<.75 else RED; c.setStrokeColor(col)
 if pct>0: c.arc(x-r,y-r,x+r,y+r,0,180*pct)
 c.setLineCap(0)
 txt(c,"EFICACIA DE BLOQUEO",x,y+15,8,TEXT,"Helvetica-Bold","center"); txt(c,f"{pct*100:.1f}%",x,y-4,22,col,"Helvetica-Bold","center"); txt(c,"bloqueadas / atacantes",x,y-18,6.5,MUTED,align="center")
 txt(c,"0",x-r+3,y-3,5.5,MUTED); txt(c,"100%",x+r-3,y-3,5.5,MUTED,align="right")
def ip_grid(c,ips,x,y,w,h):
 ips=sorted(ips,key=lambda v:tuple(int(p) for p in v.split(".") if p.isdigit()))
 if not ips:
  txt(c,"SIN EJECUCIONES DE FIREWALL-DROP",x+w/2,y+h/2,8,MUTED,"Helvetica-Bold","center"); return
 cols=2 if w<300 else 3
 rows=max(1,(len(ips)+cols-1)//cols)
 cell_w=w/cols; cell_h=h/rows
 for i,ip in enumerate(ips[:30]):
  col=i%cols; row=i//cols; xx=x+col*cell_w; yy=y+h-(row+1)*cell_h
  c.setFillColor(colors.HexColor("#eef3f4")); c.roundRect(xx+3,yy+3,cell_w-6,max(12,cell_h-6),5,fill=1,stroke=0)
  c.setFillColor(RED); c.circle(xx+13,yy+cell_h/2,3,fill=1,stroke=0)
  txt(c,ip,xx+22,yy+cell_h/2-2,6.7,TEXT,"Helvetica-Bold")
 if len(ips)>30:
  txt(c,f"+ {len(ips)-30} IPs adicionales",x+w-3,y+1,5.8,MUTED,align="right")

def page1(c,s,g,l,p,W,H):
 header(c,l,g,p,1,W,H)
 y=H-142; gap=9; x=24; kw=(W-48-gap*3)/4
 kpi(c,x,y,kw,62,s["security_count"],"EVENTOS DE SEGURIDAD","detecciones clasificadas",ORANGE)
 kpi(c,x+kw+gap,y,kw,62,s["critical_count"],"ALTA SEVERIDAD","nivel Wazuh ≥ 13",RED)
 kpi(c,x+2*(kw+gap),y,kw,62,len(s["source_ips"]),"IPS ATACANTES","orígenes observados",ORANGE2)
 kpi(c,x+3*(kw+gap),y,kw,62,len(s["firewall_ips"]),"IPS BLOQUEADAS","ejecuciones firewall-drop",RED)

 top_y=H-365; card_h=195; left_w=495; right_x=530; right_w=W-right_x-24
 box(c,24,top_y,left_w,card_h); title(c,"ACTIVIDAD POR CATEGORÍA",38,top_y+card_h-23,left_w-28,ORANGE,"volumen")
 catbars(c,s["categories"],38,top_y+30,left_w-56,card_h-68)

 box(c,right_x,top_y,right_w,card_h); title(c,"RESPUESTA AUTOMÁTICA",right_x+14,top_y+card_h-23,right_w-28,RED,"firewall-drop")
 gauge(c,len(s["firewall_ips"]),len(s["source_ips"]),right_x+right_w/2,top_y+108,56)
 txt(c,"BLOQUEOS POR REGLA",right_x+14,top_y+45,6.5,MUTED,"Helvetica-Bold")
 fw=Counter()
 for row in s["firewall_rows"]: fw[f"Regla {row['rule_id']}"]+=len(row["ips"])
 bars(c,fw.most_common(4),right_x+14,top_y+18,right_w-28,22,RED,4,75)

 bottom_y=35; bottom_h=175
 box(c,24,bottom_y,330,bottom_h); title(c,"PERFIL DE AMENAZAS",38,bottom_y+bottom_h-23,302,PURPLE,"distribución")
 vals=[]; labs=[]; cols=[]
 for key in CAT:
  v=s["categories"].get(key,{}).get("count",0)
  if v: labs.append(CAT[key]); vals.append(v); cols.append(CC[key])
 donut(c,vals,labs,108,bottom_y+82,52,cols)

 box(c,365,bottom_y,230,bottom_h); title(c,"EVOLUCIÓN",379,bottom_y+bottom_h-23,202,ORANGE,"por día")
 line(c,s.get("timeline",{}),377,bottom_y+20,206,120)

 box(c,607,bottom_y,W-631,bottom_h); title(c,"FUENTES BLOQUEADAS",621,bottom_y+bottom_h-23,W-655,RED,f"{len(s['firewall_ips'])} IPs")
 ip_grid(c,s["firewall_ips"],619,bottom_y+18,W-655,bottom_h-55)
 footer(c,W); c.showPage()

def page2(c,s,g,l,p,W,H,report):
 header(c,l,g,p,2,W,H)
 top_y=H-300; h=178; gap=12; w=(W-48-gap*2)/3
 rc=Counter()
 for info in s["categories"].values(): rc.update(info.get("rules") or {})
 rules=[(f"{k[0]} · {k[1]}",v) for k,v in rc.most_common(7)]
 systems=[(k[1],v) for k,v in s["agents"].most_common(7)]
 mitre=[(f"{mid} · {name}",v) for mid,name,_meaning,v in report.mitre_rows(s)[:7]]
 for i,(head,rows,accent) in enumerate((("TOP SISTEMAS",systems,ORANGE),("TOP REGLAS",rules,RED),("MITRE ATT&CK",mitre,PURPLE))):
  xx=24+i*(w+gap); box(c,xx,top_y,w,h); title(c,head,xx+14,top_y+h-23,w-28,accent,"por volumen")
  bars(c,rows,xx+14,top_y+25,w-28,h-62,accent,7,125)

 bottom_y=35; bottom_h=250; left_w=500
 box(c,24,bottom_y,left_w,bottom_h)
 title(c,"FIREWALL-DROP · EJECUCIONES REALES",38,bottom_y+bottom_h-23,left_w-28,RED,f"{len(s['firewall_ips'])} IPs bloqueadas")
 txt(c,"IPs provenientes de eventos Wazuh de regla 651 con comando add.",38,bottom_y+bottom_h-40,6.2,MUTED)
 ip_grid(c,s["firewall_ips"],38,bottom_y+30,left_w-28,bottom_h-82)

 right_x=534; right_w=W-right_x-24
 box(c,right_x,bottom_y,right_w,bottom_h); title(c,"SEVERIDAD Y RESPUESTA",right_x+14,bottom_y+bottom_h-23,right_w-28,ORANGE,"perfil")
 high=s["critical_count"]; total=s["security_count"]
 bars(c,[("Alta ≥13",high),("No crítica",max(0,total-high))],right_x+14,bottom_y+142,right_w-28,45,RED,2,85)
 txt(c,"COBERTURA DE RESPUESTA",right_x+14,bottom_y+116,6.5,MUTED,"Helvetica-Bold")
 gauge(c,len(s["firewall_ips"]),len(s["source_ips"]),right_x+right_w/2,bottom_y+70,43)
 txt(c,"REGLAS QUE GENERARON BLOQUEOS",right_x+14,bottom_y+26,6.2,MUTED,"Helvetica-Bold")
 blocked_rules=sorted({row["rule_id"] for row in s["firewall_rows"]})
 txt(c," · ".join(blocked_rules) if blocked_rules else "Sin ejecuciones registradas",right_x+14,bottom_y+14,6.5,TEXT,"Helvetica-Bold")
 footer(c,W); c.showPage()

def build(def build(path,s,g,start,end,label,report):
 W,H=landscape(A4); c=canvas.Canvas(str(path),pagesize=(W,H)); c.setTitle(f"OrangeBox Security Dashboard - {g}"); c.setAuthor("OrangeBox IT Services")
 now=datetime.now().astimezone(); ec=end if end.tzinfo else end.replace(tzinfo=now.tzinfo); p=f"{start:%d/%m/%Y %H:%M} — {end:%d/%m/%Y %H:%M}" if ec<=now else f"{start:%d/%m/%Y %H:%M} — ahora"
 page1(c,s,g,label,p,W,H); page2(c,s,g,label,p,W,H,report); c.save()
def send_pdf(path,subject,to):
 msg=MIMEMultipart(); msg["Subject"]=subject; msg["From"]=f"Wazuh SOC <{DEFAULT_FROM}>"; msg["To"]=to; msg.attach(MIMEText("Adjunto: OrangeBox Wazuh Security Dashboard.","plain","utf-8"))
 with open(path,"rb") as f: part=MIMEApplication(f.read(),_subtype="pdf")
 part.add_header("Content-Disposition","attachment",filename=os.path.basename(path)); msg.attach(part)
 with smtplib.SMTP(SMTP_HOST,SMTP_PORT,timeout=30) as smtp: smtp.sendmail(DEFAULT_FROM,[to],msg.as_string())
def main():
 ap=argparse.ArgumentParser(description="OrangeBox Wazuh Security Dashboard PDF"); modes=ap.add_mutually_exclusive_group(required=True)
 for x in ("today","yesterday","thisweek","lastweek","thismonth","lastmonth","thisyear","lastyear"): modes.add_argument("--"+x,action="store_true")
 modes.add_argument("--date"); ap.add_argument("--group",required=True); ap.add_argument("--output",default="/tmp/orangebox-security-dashboard.pdf"); ap.add_argument("--email",action="append")
 a=ap.parse_args(); r=report_module(); mode=a.date and f"date:{a.date}" or next(x for x in ("today","yesterday","thisweek","lastweek","thismonth","lastmonth","thisyear","lastyear") if getattr(a,x))
 now=datetime.now().astimezone(); start,end,label=r.period_bounds(mode,now); allowed=r.group_members(a.group); s=r.load_events(start,end,allowed); out=Path(a.output); out.parent.mkdir(parents=True,exist_ok=True); build(out,s,a.group,start,end,label,r)
 if a.email:
  for value in a.email:
   for to in [z.strip() for z in value.split(",") if z.strip()]:
    if not re.fullmatch(r"[^\s@]+@[^\s@]+",to): raise SystemExit(f"Dirección de correo inválida: {to}")
    send_pdf(out,f"📊 [ORANGEBOX] Dashboard de Seguridad — {a.group}",to)
 print(f"Grupo: {a.group}"); print(f"Periodo: {start:%d/%m/%Y %H:%M} — {end:%d/%m/%Y %H:%M}"); print(f"Eventos: {s['security_count']}"); print(f"IPs atacantes: {len(s['source_ips'])}"); print(f"IPs bloqueadas: {len(s['firewall_ips'])}"); print(f"Archivo: {out}")
if __name__=="__main__": main()
