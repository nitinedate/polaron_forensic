"""Update source-traced mobile flows and build a focused decryption test guide."""
from pathlib import Path
import json
import build_flows as render

ROOT = Path(__file__).resolve().parent

def node(id, text, r, c=1, kind='process'):
    return dict(id=id, text=text, r=r, c=c, kind=kind)

def edge(a, b, label=None, **kw):
    return dict(a=a, b=b, **({'label':label} if label else {}), **kw)

formats = [
    [
        "Original .crypt",
        "Historical public AES format key",
        "AES-192-ECB; complete SQLite structural checks; authenticity unverified"
    ],
    [
        "CRYPT5",
        "Already-derived 24-byte / 48-hex key, or exact original Google account",
        "AES-192-CBC; complete SQLite + quick_check; no authentication tag"
    ],
    [
        "CRYPT7 / CRYPT8",
        "Matching files/key or 32-byte AES secret",
        "AES-256-CBC; CRYPT8 gzip; complete SQLite checks; authenticity unverified"
    ],
    [
        "CRYPT9 / 10 / 11",
        "Matching files/key or raw 32-byte AES secret",
        "GCM tag when present; exact-EOF historical tagless streams remain unverified; failed tags never discarded"
    ],
    [
        "CRYPT12 / CRYPT14",
        "Matching files/key; raw / hexadecimal secret accepted",
        "AES-GCM tag and any MD5 footer required; bounded expansion"
    ],
    [
        "CRYPT15",
        "Matching encrypted_backup.key or 64-character root secret",
        "HKDF-SHA256 then AES-GCM authentication and footer validation"
    ],
    [
        "Other CRYPT extensions",
        "No validated decoder in this release",
        "Retain encrypted bytes; unsupported_crypt_version; never assume another format"
    ]
]

legacy = {
    'title':'WhatsApp / Historical CRYPT formats',
    'intro':'Historical ECB, CBC and tagless stream backups do not establish cryptographic authenticity. Recovery verifies SQLite structure and records the integrity limit on every parsed chat.',
    'height':410,
    'chart':{'nodes':[
        node('source','Retained legacy backup\nPath + source hash',0,kind='data'),
        node('version','Historical\nformat?',1,kind='decision'),
        node('account','CRYPT5: 24-byte secret\nor original Google account',2,0,'key'),
        node('static','Original .crypt\nPublic historical key',2,1,'key'),
        node('key','Matching device secret\nCRYPT7/8/9/10/11',2,2,'key'),
        node('cbc','ECB / CBC / GCM stream\nValidate exact payload',3,kind='key'),
        node('check','SQLite size +\nquick_check pass?',4,kind='decision'),
        node('blocked','Wrong input / corruption\nEncrypted evidence retained',4,2,'blocked'),
        node('copy','Derived historical DB\nNo-MAC integrity label',5,kind='data'),
    ],'edges':[edge('source','version'),edge('version','account','5'),edge('version','static','.crypt'),edge('static','cbc'),edge('version','key','7-11'),edge('account','cbc'),edge('key','cbc'),edge('cbc','check'),edge('check','blocked','No'),edge('check','copy','Yes')]},
    'notes':[['Meaning','Structural checks do not prove authenticity. Legacy chat records carry a medium confidence ceiling and the legacy_no_authentication_tag validation note.'],
             ['Account','CRYPT5 account derivation is specific to this old format. It does not extract a CRYPT14 key from ciphertext.']],
    'source':'mobile_forensic/whatsapp_crypt.py; integrity.py; parsers/messaging.py; frontend JobIntakePage.tsx'
}

payloads = {
    'title':'WhatsApp / Derived payloads before artifact parsing',
    'intro':'The materialize stage decrypts registered case bytes before native parsing, OCR, media review and text-only RAG. Original encrypted files remain in the case.',
    'height':405,
    'chart':{'nodes':[
        node('plain','Verified decrypted payload\nOriginal + plaintext hashes',0,kind='data'),
        node('kind','Database, archive\nor other file?',1,kind='decision'),
        node('db','SQLite working copy\nReuse identical snapshots',2,0,'data'),
        node('zip','ZIP + safe members\nCRC and expansion limits',2,1,'data'),
        node('other','JSON / images / binary\nTyped derived file',2,2,'data'),
        node('register','Register case-owned objects\nEncrypted-source proof',3,kind='process'),
        node('read','Verify size / hash /\ncase namespace on reads',4,kind='decision'),
        node('reject','Missing proof / tampering\nExplicit artifact error',4,2,'blocked'),
        node('parse','Native artifact parsers\nRAG / review / report inputs',5,kind='data'),
    ],'edges':[edge('plain','kind'),edge('kind','db','DB'),edge('kind','zip','ZIP'),edge('kind','other','File'),edge('db','register'),edge('zip','register'),edge('other','register'),edge('register','read'),edge('read','reject','Fail'),edge('read','parse','Pass')]},
    'notes':[['ZIPs','Retain the authenticated archive even if a member cannot be expanded. Reject traversal, Windows device names, symlinks, duplicate names and separately encrypted members. Report limits explicitly.'],
             ['Source boundary','After extraction finalization, the server reads sealed sources or verified registered derivations. It never reopens the original phone/dump folder for a newly created working copy.']],
    'source':'whatsapp_derivation.py; forensic_serial_stages.py; sqlite_counts.py; artifact_parse.py; artifact_preview.py'
}

testmatrix = {
    'title':'WhatsApp / Supported formats and executable test case',
    'intro':'The public QA files are synthetic. The CRYPT14 case includes its matching 158-byte key file; the keyless case must remain blocked.',
    'headers':['Format','Required material','Validation / result'],'rows':formats,'widths':[90,165,252],
    'notes':[['Run','From the updated project: python scripts/test-whatsapp-decryption.py --out C:/Aetheris-QA/whatsapp-case (choose an empty output folder).'],
             ['Checks','The script checks ten formats, typed payloads, key capture offset, keyless blocking, chats, a surviving deleted row, attachment reference, RAG-ready text and unchanged input hashes.'],
             ['Live status','Synthetic and PostgreSQL-compatible checks passed. No connected Android phone, native Windows device acquisition or GPU session was available for live acceptance.']],
    'source':'scripts/whatsapp_qa_fixtures.py; scripts/test-whatsapp-decryption.py; backend/tests/test_whatsapp_payloads.py'
}

mobile = json.loads((ROOT/'mobile.json').read_text())
mobile['build_tag']='MOBILE FORENSICS / PROJECT RELEASE 9'
mobile['cover_notes'][1]='Includes original .crypt and CRYPT5/7/8/9/10/11/12/14/15, private key intake, derived file registration and executable synthetic test cases.'
p=mobile['pages'][6]
for item in p['chart']['nodes']:
    if item['id']=='wa':item['text']='Supported CRYPT layout?\nOriginal / 5 / 7-12 / 14-15'
    if item['id']=='decrypt':item['text']='Decrypt matching material\nValidate by format'
    if item['id']=='rows':item['text']='Derived DB / ZIP / file\nRegister before parsing'
p=mobile['pages'][8]
p['title']='05 / WhatsApp authenticated backups'
p['intro']='Modern backups authenticate before payload expansion. Payloads can contain SQLite databases, incremental ZIPs, settings, images or binary data.'
for item in p['chart']['nodes']:
    if item['id']=='verify':item['text']='Checksum + bounded inflate\nIdentify actual payload type'
    if item['id']=='integrity':item['text']='Payload expansion\nwithin supported limits?'
    if item['id']=='derived':item['text']='Derived payload + hash\nRegister for native parsing'
p['notes'][1][1]='CRYPT15 uses HKDF-SHA256. Every key candidate is tried per source, including Business and Android profiles. Protobuf IVs avoid repeated historical guesses; source/key-set cache avoids repeat decryption.'
mobile['pages'][8]['source']='backend/app/services/mobile_forensic/whatsapp_crypt.py; whatsapp_derivation.py'
for item in mobile['pages'][17]['chart']['nodes']:
    if item['id']=='keys':item['text']='Selected backups decoded\nand format checks recorded?'
mobile['pages'][17]['notes'][0][1]='Pipeline readiness can coexist with source-access gaps. Modern backups require authenticated recovery. Unauthenticated historical results retain their integrity warning. Live acceptance also requires the intended phone bytes and recoverable records.'
mobile['pages'][25]['rows'][1]=['WhatsApp crypt7/8/9/10/11/12/14','CBC / authenticated or historical GCM','Matching files/key; legacy structural checks or modern authenticated payload']
mobile['pages'][25]['notes'][0][1]='Original .crypt uses its historical format key. CRYPT5 accepts an already-derived 24-byte key or its original account-email route; see the final format/test matrix. For external tools, document encrypted hashes, tool/version and verified output provenance before import.'
mobile['pages'][26]['notes'][1][1]='Priority key acquisition, documented protobuf IVs, source/key-set caching, shared-key handling, deduplicated derived databases, bounded ZIP expansion, batched records and 2500/800 text chunks bound resource use.'
new_titles={legacy['title'],payloads['title'],testmatrix['title'],'WhatsApp / Legacy CRYPT5, CRYPT7 and CRYPT8'}
mobile['pages']=[page for page in mobile['pages'] if page['title'] not in new_titles]+[legacy,payloads,testmatrix]
(ROOT/'mobile.json').write_text(json.dumps(mobile,indent=2)+'\n')

intake = {'title':'Key intake / what the CRYPT14 test actually supplies',
 'intro':'A CRYPT14 backup does not contain its secret. Acquisition captures the matching private file when Android access permits it, or an examiner supplies that already-collected file.',
 'height':420,
 'chart':{'nodes':[
  node('acquire','Phone acquisition\nor collected key upload',0,kind='data'),
  node('access','Private file readable?\nExisting root / run-as',1,kind='decision'),
  node('gap','Permission / sandbox gap\nNo usable key captured',1,2,'blocked'),
  node('bytes','Binary file + exit check\nReject ADB error text',2,kind='process'),
  node('valid','Recognized key\nformat and length?',3,kind='decision'),
  node('reject','Invalid / truncated key\nPrecise Intake diagnostic',3,2,'blocked'),
  node('classic','Classic 158-byte key\nBytes 126-157 => hex64',4,0,'key'),
  node('backup','E2E backup key\nRaw / Java / hex64',4,2,'key'),
  node('save','Private case Intake\nFull file + source hash',5,kind='data'),
 ],'edges':[edge('acquire','access'),edge('access','gap','No'),edge('access','bytes','Yes'),edge('bytes','valid'),edge('valid','reject','No'),edge('valid','classic','Device'),edge('valid','backup','E2E'),edge('classic','save'),edge('backup','save')]},
 'notes':[['Path','The classic source is /data/data/com.whatsapp/files/key; user profiles and com.whatsapp.w4b variants are also captured when readable. CRYPT15 uses encrypted_backup.key.'],
          ['Exact requirement','The 64 hexadecimal characters come from the collected key file, not the CRYPT14 ciphertext. Different installations/backups may need different secrets.']],
 'source':'mobile_acquire/privileged_app_pull.py; mobile_forensic/key_intake.py; routers/report.py'}

modern = json.loads(json.dumps(mobile['pages'][8]))
modern['title']='Modern CRYPT12 / CRYPT14 / CRYPT15 decryption'

reports = {'title':'Recovered data / artifacts, RAG and report evidence',
 'intro':'Recovered content follows the existing mobile processing and report paths. A recovered photo or message becomes a suspicious observation only when the evidence review supports that finding.',
 'height':420,
 'chart':{'nodes':[
  node('data','Registered derived evidence\nOriginal encrypted proof',0,kind='data'),
  node('type','Select native parser\nfrom verified file type',1,kind='decision'),
  node('chat','Chat DB / JSON / mail\nMessages + record locators',2,0,'data'),
  node('media','Images / video / files\nOCR + evidence review',2,2,'data'),
  node('normalize','Normalized artifact + state\nOriginal and output hashes',3,kind='data'),
  node('rag','Text-only RAG\n2500 chars / 800 overlap',4,0,'process'),
  node('review','Examiner observations\nMedia + factual explanation',4,2,'process'),
  node('report','Grounded report sections\nSuspicious Activity + export',5,kind='data'),
 ],'edges':[edge('data','type'),edge('type','chat','Text / DB'),edge('type','media','Media'),edge('chat','normalize'),edge('media','normalize'),edge('normalize','rag'),edge('normalize','review'),edge('rag','report'),edge('review','report')]},
 'notes':[['State','Older backup rows are historical. Explicit deletion flags and retained residuals keep their distinct labels. ZIP JSON changesets are captured as structured evidence; unrecognized incremental schemas are not silently replayed into a base database.'],
          ['Reports','Newly recovered evidence requires a new report run. Source-linked images and descriptions use the existing shared Disk/Mobile layout and Suspicious Activity section.']],
 'source':'mobile_forensic/parsers/; mobile_rag.py; suspicious_activity.py; report_generator.py'}

commands = {'title':'Run the supplied case / Windows or Python environment',
 'intro':'Use the updated application environment, or install its backend requirements. Python 3.11+ is required. The fixture manifest clearly marks the included fixed keys as public synthetic data.',
 'headers':['Step','Command / expected result'],'widths':[120,387],
 'rows':[
  ['Synthetic acceptance','python scripts/test-whatsapp-decryption.py --out C:/Aetheris-QA/whatsapp-case'],
  ['Expected test output','status=passed; 12 checks; whatsapp_synthetic_test_results.json and original/derived synthetic files'],
  ['Provided CRYPT14 file','python scripts/recover-whatsapp.py --source C:/QA/synthetic_inputs/WhatsApp/Databases/msgstore.db.crypt14 --key C:/QA/synthetic_inputs/data/data/com.whatsapp/files/key --out C:/QA/decoded-crypt14'],
  ['All fixture formats','python scripts/recover-whatsapp.py --source C:/QA/synthetic_inputs --legacy-account whatsapp-qa@example.test --out C:/QA/decoded-all'],
  ['Keyless negative case','Repeat the CRYPT14 command without --key. Expect exit code 2, no derived database and key_material_missing_or_invalid.'],
  ['Application case','Acquire/import the originals; capture or upload matching keys in Intake; save; Reprocess mobile evidence when idle; inspect per-file status, WhatsApp Messages, Files and report observations.'],
 ],
 'notes':[['Output directory','Keep recovery output outside the input evidence directory. Original backup and key files are never rewritten.'],
          ['Test integrity','The scripts verify expected plaintext hashes, chats, surviving deleted rows, attachment references and unchanged input hashes. A supplied key from another installation is expected to fail.']],
 'source':'scripts/recover-whatsapp.py; scripts/test-whatsapp-decryption.py'}

negative = {'title':'Failure cases / honest results for every source',
 'headers':['Input condition','Expected behavior'],'widths':[178,329],
 'rows':[
  ['CRYPT14 only; no matching key','Keep encrypted source; key_material_missing_or_invalid; no fabricated key or plaintext.'],
  ['ADB error saved as key','Reject during acquisition/Intake. It is not 158-byte usable key evidence, even if padded to that length.'],
  ['Wrong installation key','Try other distinct collected keys. If none match, keep key_mismatch_or_damaged_backup.'],
  ['Altered ciphertext / tag / MD5','Do not expose unauthenticated data; keep the original and exact diagnostic.'],
  ['CRYPT5 without a matching 24-byte key or account','legacy_account_required; a modern 32-byte backup key is insufficient.'],
  ['Unknown CRYPT version','unsupported_crypt_version; preserve encrypted bytes and report the unsupported capability.'],
  ['Unsafe / oversize ZIP members','Retain authenticated ZIP, expand only permitted CRC-checked members and list every expansion gap.'],
  ['Missing or tampered derived object','Reject namespace, source-link, size or hash mismatch before parsing/preview.'],
 ],
 'notes':[['Limits','WhatsApp backup keys do not decrypt Android filesystem encryption, unrelated applications, password-protected documents or transport-encrypted media with separate keys. Missing/overwritten data cannot be reconstructed by a parser.']],
 'source':'backend/tests/test_whatsapp_payloads.py; test_whatsapp_derivation.py; test_whatsapp_key_intake.py'}

verification = {'title':'Verification scope / performance and live acceptance',
 'headers':['Verified in this update','Practical scope'],'widths':[190,317],
 'rows':[
  ['Independent synthetic encoders','Original .crypt and CRYPT5/7/8/9/10/11/12/14/15 use independent cryptography AES/HKDF fixtures; pre-existing independent wa-crypt-tools vectors remain covered.'],
  ['Portable 12-check case','Key offset, keyless failure, ten supported layouts, ZIP/mail/image/JSON/binary recovery, chats, deleted row, media reference, RAG text and preserved hashes.'],
  ['PostgreSQL-compatible service checks','Real service SQL, multi-key Intake, deduplicated registration, parser storage, message browser, RAG chunks, case namespace and tamper rejection.'],
  ['Frontend compilation','Unified, Android and iOS builds include CRYPT5 48-hex/account input, per-file authentication status and preserved key uploads.'],
  ['Resource changes','Documented IV dispatch; bounded fallback; source/key-set cache; no duplicate DB parses; bounded ZIP expansion; cooperative pause and per-source progress.'],
  ['Live hardware still required','No physical phone, native Windows phone pull or GPU session was connected. Real case decryption also needs its matching keys; synthetic QA secrets are unusable for real cases.'],
 ],
 'notes':[['Coverage','This verifies supported code paths. It does not establish recovery of every possible encrypted format or every deleted mobile artifact.']],
 'source':'WHATSAPP-CRYPT-RELEASE.md; WHATSAPP-CRYPT-MANIFEST.json; LIVE-PHONE-GPU-VERIFICATION.md'}

crypto={'filename':'WhatsApp-Decryption-Test-Cases.pdf','title':'WhatsApp Decryption\nFlows and Test Cases',
 'short':'WhatsApp Decryption','subtitle':'Mobile extraction → matching key intake → derived evidence → RAG and reports',
 'accent':'#A895DD','build_tag':'WHATSAPP RECOVERY / PROJECT RELEASE 9',
 'cover_notes':['Supported: original .crypt; CRYPT5, 7, 8, 9, 10, 11, 12, 14 and 15.',
                'Includes a runnable synthetic CRYPT14 case and missing/wrong-key behavior.',
                'A CRYPT14 file alone cannot yield its key. Unsupported versions remain visible as encrypted evidence.'],
 'pages':[testmatrix,intake,modern,legacy,payloads,reports,commands,negative,verification]}
(ROOT/'whatsapp.json').write_text(json.dumps(crypto,indent=2)+'\n')
render.build(mobile)
render.build(crypto)
(ROOT.parent/'flow-qa/whatsapp-crypt9-document-layout.json').write_text(json.dumps(render.BOUND,indent=2)+'\n')
print(json.dumps({'mobile_pages':len(mobile['pages'])+2,'whatsapp_pages':len(crypto['pages'])+2}))
