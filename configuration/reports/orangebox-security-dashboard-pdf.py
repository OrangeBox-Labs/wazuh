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
def bars(c,rows,x,y,w,h,accent,max_items=6,labelw=120):
 rows=rows[:max_items]
 if not rows: txt(c,"SIN DATOS",x+w/2,y+h/2,9,MUTED,"Helvetica-Bold","center"); return
 mv=max(float(v) for _,v in rows) or 1; rh=h/len(rows)
 for i,(lab,val) in enumerate(rows):
  yy=y+h-(i+1)*rh+rh*.18; txt(c,lab,x,yy+rh*.32,7.2,TEXT,"Helvetica-Bold")
  bx=x+labelw; bw=w-labelw-48; c.setFillColor(colors.HexColor("#e9eef0")); c.roundRect(bx,yy,bw,9,4.5,fill=1,stroke=0)
  c.setFillColor(accent); c.roundRect(bx,yy,max(4,bw*float(val)/mv),9,4.5,fill=1,stroke=0); txt(c,n(val),x+w,yy+rh*.32,7.2,TEXT,"Helvetica-Bold","right")
def catbars(c,cats,x,y,w,h):
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
def page1(c,s,g,l,p,W,H):
 header(c,l,g,p,1,W,H); y=H-142; gap=9; x=28; kw=(W-56-gap*3)/4
 kpi(c,x,y,kw,65,s["security_count"],"Eventos","detecciones clasificadas",ORANGE); kpi(c,x+kw+gap,y,kw,65,s["critical_count"],"Alta severidad","nivel Wazuh ≥ 13",RED); kpi(c,x+2*(kw+gap),y,kw,65,len(s["source_ips"]),"IPs atacantes","orígenes observados",ORANGE2); kpi(c,x+3*(kw+gap),y,kw,65,len(s["firewall_ips"]),"IPs bloqueadas","Active Response · firewall-drop",RED)
 py=H-390; ph=205
 box(c,28,py,500,ph); title(c,"ACTIVIDAD POR CATEGORÍA",40,py+ph-23,476,ORANGE,"detecciones"); catbars(c,s["categories"],40,py+25,476,ph-55)
 box(c,540,py,274,ph); title(c,"RESPUESTA AUTOMÁTICA",552,py+ph-23,250,RED,"firewall-drop"); gauge(c,len(s["firewall_ips"]),max(1,len(s["source_ips"])),677,py+111,68); txt(c,f"{n(len(s['firewall_ips']))} bloqueadas de {n(len(s['source_ips']))} IPs observadas",677,py+37,7,MUTED,align="center")
 ty=54; th=155; box(c,28,ty,786,th); title(c,"EVOLUCIÓN DIARIA",40,ty+th-23,762,ORANGE,"detecciones clasificadas"); line(c,s.get("timeline",{}),40,ty+18,762,th-48); footer(c,W); c.showPage()
def page2(c,s,g,l,p,W,H,report):
 header(c,l,g,p,2,W,H); y=H-300; h=178; gap=12; w=(W-56-gap*2)/3
 rc=Counter()
 for info in s["categories"].values(): rc.update(info.get("rules") or {})
 rules=[(f"{k[0]} · {k[1]}" if isinstance(k,tuple) else str(k),v) for k,v in rc.most_common(7)]
 systems=[(k[1] if isinstance(k,tuple) else str(k),v) for k,v in s["agents"].most_common(7)]
 mitre=[(f"{mid} · {name}",v) for mid,name,_meaning,v in report.mitre_rows(s)[:7]]
 for i,(head,rows,accent) in enumerate((("TOP SISTEMAS",systems,ORANGE),("TOP REGLAS",rules,RED),("MITRE ATT&CK",mitre,PURPLE))):
  xx=28+i*(w+gap); box(c,xx,y,w,h); title(c,head,xx+12,y+h-23,w-24,accent,"por volumen" if i<2 else "técnicas observadas"); bars(c,rows,xx+12,y+20,w-35,h-57,accent,7,120)
 ly=54; lh=210; box(c,28,ly,500,lh); title(c,"ACTIVE RESPONSE · BLOQUEOS",40,ly+lh-23,476,RED,"ejecuciones reales de firewall-drop")
 fw=Counter()
 for row in s["firewall_rows"]: fw[row["agent_name"]]+=len(row["ips"])
 bars(c,fw.most_common(),40,ly+25,476,lh-62,RED,8,120)
 box(c,540,ly,274,lh); title(c,"DISTRIBUCIÓN",552,ly+lh-23,250,CYAN,"detecciones")
 labs=[]; vals=[]; cols=[]
 for k in CAT:
  v=s["categories"].get(k,{}).get("count",0)
  if v: labs.append(CAT[k]); vals.append(v); cols.append(CC[k])
 donut(c,vals,labs,612,ly+100,54,cols)
 txt(c,"FUENTES BLOQUEADAS",650,ly+55,7,MUTED,"Helvetica-Bold"); txt(c,n(len(s["firewall_ips"])),650,ly+37,18,RED,"Helvetica-Bold"); txt(c,"registros de ejecución",650,ly+22,6.5,MUTED)
 footer(c,W); c.showPage()
def build(path,s,g,start,end,label,report):
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
