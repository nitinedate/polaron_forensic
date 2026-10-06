"""Source rules, exact evidence image hashes and shared report formation."""
import hashlib
import io
from pathlib import Path
from PIL import Image
import pytest
from app.services import suspicious_activity as review
from app.services.report_renderer import SECTION_ORDER,MOBILE_SECTION_ORDER,section_title


def test_message_requires_an_explicit_contextual_signal():
    assert not review.review_signals({'artifact_type':'app_message','data':{'body':'The password policy was updated. Pay the approved invoice next week.'}})
    rows=review.review_signals({'artifact_type':'app_message','data':{'body':'Please send your OTP to me immediately.'}})
    assert rows[0]['category']=='credential_request'
    assert 'send your OTP' in rows[0]['excerpt']
    assert 'authorization' in rows[0]['explanation']


@pytest.mark.parametrize('artifact_type',['binary_string','binary_field','encrypted_or_unreadable_database','recovered_chat_candidate'])
def test_unverified_bytes_are_not_promoted_to_chats(artifact_type):
    assert review.review_signals({'artifact_type':artifact_type,'data':{'text':'Please send your OTP immediately'}})==[]


def test_download_and_application_cues_do_not_claim_malware():
    rows=review.review_signals({'artifact_type':'browser_download','data':{'local_path':'/Downloads/report.pdf.exe'}})
    assert {row['category'] for row in rows}=={'executable_download','disguised_extension'}
    assert 'not proof of malware' in rows[0]['explanation']
    assert not review.review_signals({'artifact_type':'document','data':{'path':'innocent.apk'}})
    assert not review.review_signals({'artifact_type':'installed_app','data':{'package':'com.whatsapp'}})


def picture_card(tmp_path):
    image=Image.new('RGB',(720,400),'#ccddea');buf=io.BytesIO();image.save(buf,format='PNG');blob=buf.getvalue()
    sha=hashlib.sha256(blob).hexdigest();job='00000000-0000-0000-0000-000000000001';source_sha='a'*64
    object_root=tmp_path/'objects';path=object_root/f'forensic-observations/{job}/{source_sha}/{sha}.png';path.parent.mkdir(parents=True);path.write_bytes(blob)
    return {'id':'fixture-evidence','job_id':job,'job_artifact_id':'00000000-0000-0000-0000-000000000002',
            'category':'image','source_record_id':'fixture/frame/0','source_path':'/DCIM/fixture.png',
            'source_sha256':source_sha,'frame_sha256':sha,'derived_frame_uri':path.as_uri(),
            'frame_index':0,'timestamp_seconds':None,'timestamp_utc':None,
            'explanation':'Synthetic QA fixture: review description for layout validation only.',
            'excerpt':'','method':'visual_model','model':'mock-vision'},blob,object_root


def test_report_image_rejects_hash_mismatch_and_unrelated_paths(tmp_path,monkeypatch):
    card,blob,root=picture_card(tmp_path)
    monkeypatch.setattr('app.services.storage._local_root',lambda:root)
    assert review.evidence_image_bytes(card)==blob
    Path(card['derived_frame_uri'][7:]).write_bytes(b'wrong bytes')
    with pytest.raises(ValueError,match='hash'):
        review.evidence_image_bytes(card)
    with pytest.raises(ValueError,match='outside'):
        review.evidence_image_bytes({**card,'derived_frame_uri':'file:///etc/passwd'})
    with pytest.raises(ValueError,match='outside'):
        review.evidence_image_bytes({**card,'derived_frame_uri':'https://example.test/evidence.png'})


def test_disk_mobile_use_corresponding_structure_and_same_headings():
    translated=[{'forensic_imaging':'extraction_summary','os_information':'device_information'}.get(key,key) for key in SECTION_ORDER]
    assert MOBILE_SECTION_ORDER==translated
    assert 'suspicious_activity' in SECTION_ORDER and 'artifact_summary' in MOBILE_SECTION_ORDER
    for key in {'tools_used','artifact_summary','objectives_procedure_observation','suspicious_activity','annexure','final_analysis_summary','appendix'}:
        assert section_title(key,mobile=True)==section_title(key)


def test_pdf_and_word_contain_actual_verified_picture_and_caption(tmp_path,monkeypatch):
    import fitz
    from zipfile import ZipFile
    from app.services.report_pdf_export import build_report_pdf
    from app.services.report_docx_export import build_report_docx
    card,blob,root=picture_card(tmp_path);monkeypatch.setattr('app.services.storage._local_root',lambda:root)
    notes='### Examiner observations\n\nExaminer verified the source image against the acquired evidence.'
    sections=[{'section_key':'suspicious_activity','content_md':'','structured_json':{'suspicious_activity':[card],'review_note':review.REVIEW_NOTE,'examiner_observations_md':notes}}]
    pdf=build_report_pdf(sections,order=['suspicious_activity'],mobile=True)
    document=fitz.open(stream=pdf,filetype='pdf')
    assert len(document)==2 and 'fixture.png' in document[0].get_text()
    assert 'Examiner verified the source image' in document[1].get_text()
    assert len(document[0].get_images())==1
    assert 'pending examiner review' in document[0].get_text()
    word=build_report_docx(sections,order=['suspicious_activity'],mobile=True)
    with ZipFile(io.BytesIO(word)) as archive:
        assert any(name.startswith('word/media/') for name in archive.namelist())
        assert any(archive.read(name)==blob for name in archive.namelist() if name.startswith('word/media/'))
        assert 'fixture.png' in archive.read('word/document.xml').decode()
        assert 'Examiner verified the source image' in archive.read('word/document.xml').decode()
    assert 'Examiner verified the source image' in review.suspicious_html(sections[0])
