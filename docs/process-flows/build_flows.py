from __future__ import annotations
import json, math, zipfile
from pathlib import Path
from html import escape
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.platypus import Paragraph
from reportlab.lib.styles import ParagraphStyle
import fitz

ROOT=Path(__file__).resolve().parent
OUT=ROOT.parent/'flow-deliverables'
OUT.mkdir(exist_ok=True)
FONT=str(ROOT/'fonts') if (ROOT/'fonts/DejaVuSans.ttf').is_file() else '/usr/share/fonts/truetype/dejavu'
pdfmetrics.registerFont(TTFont('Sans',FONT+'/DejaVuSans.ttf'))
pdfmetrics.registerFont(TTFont('SansBold',FONT+'/DejaVuSans-Bold.ttf'))
pdfmetrics.registerFontFamily('Sans',normal='Sans',bold='SansBold',italic='Sans',boldItalic='SansBold')
W,H=A4; M=44; CW=W-2*M
NAVY=colors.HexColor('#142D47'); INK=colors.HexColor('#24394D'); MUTED=colors.HexColor('#53697C')
PALETTE={'process':('#EDF4FD','#6D94C4'),'decision':('#FFF3DC','#BD8A30'),'data':('#E8F5EF','#539A78'),'blocked':('#FCECEE','#BD6570'),'key':('#F1EAFE','#9170B4'),'external':('#F0F2F4','#84909B')}
NORMAL=ParagraphStyle('normal',fontName='Sans',fontSize=10.25,leading=14.2,textColor=INK,spaceAfter=0)
SMALL=ParagraphStyle('small',parent=NORMAL,fontSize=8.5,leading=11.5)
NODE=ParagraphStyle('node',parent=NORMAL,fontSize=9.25,leading=11.7,alignment=1)
TABLE=ParagraphStyle('table',parent=NORMAL,fontSize=9.15,leading=12.5)
HEADING=ParagraphStyle('heading',parent=NORMAL,fontName='SansBold',fontSize=17,leading=21,textColor=NAVY)
BOUND=[]

def para(c,text,x,y,w,style=NORMAL,limit=48):
    p=Paragraph(text,style); _,height=p.wrap(w,9999)
    if y-height<limit: raise ValueError(f'Content overflow: {text[:65]} (bottom={y-height:.1f})')
    p.drawOn(c,x,y-height)
    return y-height

def clean(s): return escape(str(s)).replace('\n','<br/>')

def label(c,text,x,y,color=INK):
    style=ParagraphStyle('edge',parent=SMALL,fontName='SansBold',fontSize=8.0,leading=9.5,alignment=1,textColor=color)
    p=Paragraph(clean(text),style); tw=min(108,max(25,pdfmetrics.stringWidth(str(text),'SansBold',8.0)+10))
    _,th=p.wrap(tw,99)
    c.setFillColor(colors.white); c.roundRect(x-tw/2,y-th/2-2,tw,th+4,3,fill=1,stroke=0)
    p.drawOn(c,x-tw/2,y-th/2)

def chart(c,spec,top,height):
    nodes=spec['nodes']; maxr=max(n['r'] for n in nodes)
    dy=(height-66)/max(1,maxr)
    if maxr==0: dy=0
    xs=[M+78,M+CW/2,M+CW-78]
    geom={n['id']:(xs[n.get('c',1)],top-33-n['r']*dy,144,60 if n.get('kind')=='decision' else 54) for n in nodes}
    # Route orthogonal arrows before nodes so their interiors stay clean.
    for e in spec.get('edges',[]):
        a,b=e['a'],e['b']; ax,ay,aw,ah=geom[a]; bx,by,bw,bh=geom[b]
        kind=e.get('kind','normal'); color=colors.HexColor('#AB5566') if kind=='blocked' else colors.HexColor('#496C8B')
        c.setStrokeColor(color); c.setLineWidth(1.0)
        c.setDash(3,2) if kind=='external' else c.setDash()
        if 'points' in e:
            # Custom points are fractions of the chart width and height.
            pts=[(M+v[0]*CW,top-v[1]*height) for v in e['points']]
        elif abs(ay-by)<1:
            direction=1 if bx>ax else -1
            pts=[(ax+direction*aw/2,ay),(bx-direction*bw/2,by)]
        elif abs(ax-bx)<1 and by<ay:
            pts=[(ax,ay-ah/2),(bx,by+bh/2)]
        elif by>ay:
            side=e.get('side','left'); sx=M+4 if side=='left' else W-M-4
            pts=[(ax+(-aw/2 if side=='left' else aw/2),ay),(sx,ay),(sx,by),(bx+(-bw/2 if side=='left' else bw/2),by)]
        else:
            mid=(ay-ah/2+by+bh/2)/2
            pts=[(ax,ay-ah/2),(ax,mid),(bx,mid),(bx,by+bh/2)]
        p=c.beginPath(); p.moveTo(*pts[0])
        for q in pts[1:]: p.lineTo(*q)
        c.drawPath(p);c.setDash()
        end=pts[-1]; prev=next((q for q in reversed(pts[:-1]) if q!=end),pts[0])
        dx=end[0]-prev[0];dy2=end[1]-prev[1]; length=math.hypot(dx,dy2) or 1
        ux,uy=dx/length,dy2/length; size=5
        ar=c.beginPath(); ar.moveTo(*end);ar.lineTo(end[0]-ux*size-uy*2.5,end[1]-uy*size+ux*2.5);ar.lineTo(end[0]-ux*size+uy*2.5,end[1]-uy*size-ux*2.5);ar.close()
        c.setFillColor(color);c.drawPath(ar,fill=1,stroke=0)
        if e.get('label'):
            if 'label_pos' in e: lx,ly=M+e['label_pos'][0]*CW,top-e['label_pos'][1]*height
            else:
                segment=max(zip(pts,pts[1:]),key=lambda pq:math.dist(*pq))
                lx=(segment[0][0]+segment[1][0])/2;ly=(segment[0][1]+segment[1][1])/2
                if abs(segment[0][0]-segment[1][0])<1: lx+=24
                else: ly+=11
            label(c,e['label'],lx,ly,color)
    for n in nodes:
        x,y,w,h=geom[n['id']]; kind=n.get('kind','process'); fill,stroke=PALETTE[kind]
        c.setFillColor(colors.HexColor(fill)); c.setStrokeColor(colors.HexColor(stroke));c.setLineWidth(.8)
        if kind=='decision':
            p=c.beginPath();p.moveTo(x,y+h/2);p.lineTo(x+w/2,y);p.lineTo(x,y-h/2);p.lineTo(x-w/2,y);p.close();c.drawPath(p,fill=1,stroke=1);pw=w*.63
        else:
            if kind=='external': c.setDash(3,2)
            c.roundRect(x-w/2,y-h/2,w,h,7,stroke=1,fill=1);c.setDash();pw=w-13
        p=Paragraph(clean(n['text']),NODE); _,ph=p.wrap(pw,999)
        if ph>h-7: raise ValueError(f'Node text overflow {n["id"]}: {n["text"]!r} ({ph})')
        p.drawOn(c,x-pw/2,y-ph/2)
    BOUND.append({'chart':spec.get('name',''), 'node_count':len(nodes),'height':height})
    return top-height

def footer(c,title,page,total,accent):
    c.setStrokeColor(colors.HexColor('#CBD5DE'));c.setLineWidth(.4);c.line(M,37,W-M,37)
    c.setFont('Sans',7.4);c.setFillColor(MUTED);c.drawString(M,24,title+' | 06 October 2026')
    c.setFont('SansBold',7.8);c.drawRightString(W-M,24,f'{page} / {total}')
    c.setFillColor(accent);c.rect(M,H-21,34,3,fill=1,stroke=0)

def notes(c,items,y):
    if not items:return y
    for key,text in items:
        y-=7
        y=para(c,f'<b>{clean(key)}</b>  {clean(text)}',M,y,CW,NORMAL)
    return y

def table(c,headers,rows,y,widths=None):
    widths=widths or [CW/len(headers)]*len(headers)
    matrix=[headers]+rows
    for ri,row in enumerate(matrix):
        st=ParagraphStyle('thead',parent=TABLE,fontName='SansBold',textColor=colors.white) if ri==0 else TABLE
        ps=[];heights=[]
        for val,wi in zip(row,widths):
            p=Paragraph(clean(val),st);_,ph=p.wrap(wi-14,999);ps.append(p);heights.append(ph)
        rh=max(heights)+14
        if y-rh<44:raise ValueError(f'Table overflow {str(row)[:80]}')
        c.setFillColor(NAVY if ri==0 else colors.HexColor('#F3F6F9') if ri%2 else colors.white)
        c.rect(M,y-rh,CW,rh,fill=1,stroke=0)
        x=M
        for p,wi in zip(ps,widths): p.drawOn(c,x+7,y-7-p.height);x+=wi
        c.setStrokeColor(colors.HexColor('#D3DEE7'));c.setLineWidth(.35);c.line(M,y-rh,W-M,y-rh)
        y-=rh
    return y

def build(data):
    path=OUT/data['filename']; total=len(data['pages'])+2
    accent=colors.HexColor(data['accent'])
    c=canvas.Canvas(str(path),pagesize=A4,pageCompression=1)
    c.setTitle(data['title']);c.setAuthor('Aetheris engineering documentation');c.setSubject('Source-traced extraction, evidence and report workflows')
    c.setFillColor(NAVY);c.rect(0,0,W,H,fill=1,stroke=0)
    c.setFillColor(accent);c.rect(M,H-103,75,5,fill=1,stroke=0)
    c.setFont('SansBold',12);c.setFillColor(colors.HexColor('#D7E4F1'));c.drawString(M,H-80,'AETHERIS / PROCESS REFERENCE')
    cover=ParagraphStyle('cover',fontName='SansBold',fontSize=32,leading=39,textColor=colors.white)
    y=para(c,clean(data['title']),M,H-135,CW,cover)
    y=para(c,clean(data['subtitle']),M,y-25,CW,ParagraphStyle('sub',parent=NORMAL,fontSize=13,leading=19,textColor=colors.HexColor('#DCE8F3')))
    for line in data['cover_notes']:
        y=para(c,clean(line),M,y-22,CW,ParagraphStyle('covernote',parent=NORMAL,fontSize=10.8,leading=16,textColor=colors.HexColor('#DCE8F3')))
    c.setFont('SansBold',10);c.setFillColor(accent);c.drawString(M,105,data.get('build_tag','SOURCE REVIEW + SCANNER RELEASE 1.5.3-v45.7'))
    c.setFont('Sans',9);c.setFillColor(colors.white);c.drawString(M,80,'06 October 2026   |   Separate execution paths, shared evidence rules')
    c.bookmarkPage('cover');c.addOutlineEntry('Cover','cover',0,False);c.showPage()
    footer(c,data['short'],2,total,accent);c.bookmarkPage('contents');c.addOutlineEntry('Contents','contents',0,False)
    y=para(c,'Contents and diagram key',M,H-57,CW,HEADING)-16
    style=ParagraphStyle('toc',parent=NORMAL,fontSize=9.6,leading=13.0)
    for idx,p in enumerate(data['pages'],3):
        c.setFont('SansBold',9);c.setFillColor(accent);c.drawRightString(W-M,y-10,str(idx))
        y=para(c,clean(p['title']),M,y,CW-29,style)-4
        c.linkRect('',f'p{idx}',(M,y,W-M,y+17),relative=0,thickness=0)
    y-=9
    y=para(c,'<b>Diagram key</b>',M,y,CW,NORMAL)-8
    key=[('process','Process'),('decision','Gate / branch'),('data','Retained evidence'),('key','Key / crypto'),('blocked','Gap / failure'),('external','External workflow')]
    for i,(kind,title) in enumerate(key):
        col=i%3;row=i//3;x=M+col*CW/3;yy=y-row*23
        c.setFillColor(colors.HexColor(PALETTE[kind][0]));c.setStrokeColor(colors.HexColor(PALETTE[kind][1]));c.roundRect(x,yy-12,14,12,3,fill=1,stroke=1)
        c.setFont('Sans',8.3);c.setFillColor(INK);c.drawString(x+21,yy-10,title)
    y-=60
    para(c,'Solid arrows show implemented transitions. Dashed arrows show an explicitly external or conditional path. A gap is evidence of a limitation; it does not establish that the requested data never existed.',M,y,CW,SMALL)
    c.showPage()
    for idx,p in enumerate(data['pages'],3):
        footer(c,data['short'],idx,total,accent);c.bookmarkPage(f'p{idx}');c.addOutlineEntry(p['title'],f'p{idx}',0,False)
        c.setFont('SansBold',8.5);c.setFillColor(accent);c.drawString(M,H-48,p.get('eyebrow',data['short'].upper()))
        y=para(c,clean(p['title']),M,H-62,CW,HEADING)-10
        if p.get('intro'):y=para(c,clean(p['intro']),M,y,CW,NORMAL)-12
        if p.get('chart'):
            height=p.get('height',415)
            y=chart(c,p['chart'],y,height)-9
        if p.get('headers'):y=table(c,p['headers'],p['rows'],y,p.get('widths'))-8
        y=notes(c,p.get('notes',[]),y)
        if p.get('source'):
            y-=10
            y=para(c,'<b>Implementation:</b> '+clean(p['source']),M,y,CW,SMALL)
        if p.get('paragraphs'):
            for text in p['paragraphs']:
                y=para(c,clean(text),M,y-10,CW,NORMAL)
        c.showPage()
    c.save()
    pdf=fitz.open(path)
    if len(pdf)!=total:raise AssertionError((path,len(pdf),total))
    return path,total


def make_odt(data,pdf_path):
    """Editable text plus embedded flowchart pages; no fabricated evidence images."""
    from xml.sax.saxutils import escape as xe
    odt=OUT/'Vulnerability-Scanner-Process-Flows.odt'
    pdf=fitz.open(pdf_path)
    content=[];images=[]
    for index,page in enumerate(pdf):
        content.append(f'<text:h text:outline-level="1">{xe(data["title"] if index==0 else "Contents" if index==1 else data["pages"][index-2]["title"])}</text:h>')
        if index>1:
            p=data['pages'][index-2]
            if p.get('intro'):content.append(f'<text:p>{xe(p["intro"])}</text:p>')
            if p.get('chart'):
                pix=page.get_pixmap(matrix=fitz.Matrix(1.4,1.4))
                # The embedded page includes labels and notes; editable prose follows.
                name=f'Pictures/flow-{index+1:02d}.png';images.append((name,pix.tobytes('png')))
                content.append(f'<text:p><draw:frame draw:name="Flow {index+1}" text:anchor-type="as-char" svg:width="16cm" svg:height="22.63cm"><draw:image xlink:href="{name}" xlink:type="simple" xlink:show="embed" xlink:actuate="onLoad"/></draw:frame></text:p>')
            if p.get('headers'):
                content.append('<table:table table:name="Table'+str(index)+'">')
                for row in [p['headers']]+p['rows']:
                    content.append('<table:table-row>'+''.join('<table:table-cell office:value-type="string"><text:p>'+xe(str(cell))+'</text:p></table:table-cell>' for cell in row)+'</table:table-row>')
                content.append('</table:table>')
            for key,text in p.get('notes',[]):content.append(f'<text:p>{xe(key+": "+text)}</text:p>')
            if p.get('source'):content.append(f'<text:p>{xe("Implementation: "+p["source"])}</text:p>')
        else:
            for line in data['cover_notes'] if index==0 else [str(i+3)+'. '+p['title'] for i,p in enumerate(data['pages'])]:content.append(f'<text:p>{xe(line)}</text:p>')
    ns='xmlns:office="urn:oasis:names:tc:opendocument:xmlns:office:1.0" xmlns:text="urn:oasis:names:tc:opendocument:xmlns:text:1.0" xmlns:draw="urn:oasis:names:tc:opendocument:xmlns:drawing:1.0" xmlns:table="urn:oasis:names:tc:opendocument:xmlns:table:1.0" xmlns:xlink="http://www.w3.org/1999/xlink" xmlns:svg="urn:oasis:names:tc:opendocument:xmlns:svg-compatible:1.0" xmlns:style="urn:oasis:names:tc:opendocument:xmlns:style:1.0" xmlns:fo="urn:oasis:names:tc:opendocument:xmlns:xsl-fo-compatible:1.0"'
    xml=f'<?xml version="1.0" encoding="UTF-8"?><office:document-content {ns} office:version="1.3"><office:automatic-styles/><office:body><office:text>{"".join(content)}</office:text></office:body></office:document-content>'
    styles=f'<?xml version="1.0" encoding="UTF-8"?><office:document-styles {ns} office:version="1.3"><office:styles><style:default-style style:family="paragraph"><style:paragraph-properties fo:margin-bottom="0.22cm"/><style:text-properties style:font-name="DejaVu Sans" fo:font-size="10pt"/></style:default-style></office:styles><office:automatic-styles><style:page-layout style:name="A4"><style:page-layout-properties fo:page-width="21cm" fo:page-height="29.7cm" fo:margin="2cm"/></style:page-layout></office:automatic-styles><office:master-styles><style:master-page style:name="Standard" style:page-layout-name="A4"/></office:master-styles></office:document-styles>'
    entries=[('/', 'application/vnd.oasis.opendocument.text'),('content.xml','text/xml'),('styles.xml','text/xml')]+[(n,'image/png') for n,_ in images]
    manifest='<?xml version="1.0" encoding="UTF-8"?><manifest:manifest xmlns:manifest="urn:oasis:names:tc:opendocument:xmlns:manifest:1.0" manifest:version="1.3">'+''.join(f'<manifest:file-entry manifest:full-path="{n}" manifest:media-type="{t}"/>' for n,t in entries)+'</manifest:manifest>'
    with zipfile.ZipFile(odt,'w',compression=zipfile.ZIP_DEFLATED) as z:
        z.writestr('mimetype','application/vnd.oasis.opendocument.text',compress_type=zipfile.ZIP_STORED)
        z.writestr('content.xml',xml);z.writestr('styles.xml',styles);z.writestr('META-INF/manifest.xml',manifest)
        for n,img in images:z.writestr(n,img)
    return odt

if __name__=='__main__':
    results=[]
    for name in ('disk','mobile','scanner','service_guide','whatsapp'):
        data=json.loads((ROOT/f'{name}.json').read_text())
        path,count=build(data);results.append({'file':str(path),'pages':count})
        if name=='scanner':results.append({'file':str(make_odt(data,path)),'editable':'Text and tables; embedded diagrams'})
    (OUT/'document-qa.json').write_text(json.dumps({'documents':results,'charts':BOUND},indent=2))
    print(json.dumps(results,indent=2))
